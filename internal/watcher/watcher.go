package watcher

import (
	"encoding/base64"
	"log"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

func CreateAllowDirWatcher(allowFile string) (func() [][]byte, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	allowDir := path.Dir(allowFile)

	slog.Info("listening for allowed public keys", "allow-file", allowFile)

	var allowKeys atomic.Value

	readAllowKeys := func(filename string) {
		content, err := os.ReadFile(filename)
		if err != nil {
			log.Printf("unable to read allow file:%v\n", err)
			return
		}
		allows := strings.Split(string(content), "\n")
		var tempAllows [][]byte
		for _, allow := range allows {
			k, err := base64.StdEncoding.DecodeString(allow)
			if err != nil || len(k) != 32 {
				log.Printf("invalid wireguard public key: '%s'\n", allow)
				continue
			}
			tempAllows = append(tempAllows, k)
		}
		allowKeys.Store(tempAllows)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				log.Println("event:", event)
				if event.Has(fsnotify.Write) {
					if event.Name != allowFile {
						continue
					}
					log.Println("modified file:", event.Name)
					readAllowKeys(event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	// Add a path.
	err = watcher.Add(allowDir)
	if err != nil {
		return nil, err
	}

	readAllowKeys(allowFile)

	return func() [][]byte {
		return allowKeys.Load().([][]byte)
	}, nil
}
