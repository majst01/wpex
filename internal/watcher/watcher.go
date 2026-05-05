package watcher

import (
	"encoding/base64"
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
			slog.Error("unable to read allow file", "error", err)
			return
		}
		allows := strings.Split(string(content), "\n")
		var tempAllows [][]byte
		slog.Info("reading allowed keys")
		for _, allow := range allows {
			k, err := base64.StdEncoding.DecodeString(allow)
			if err != nil || len(k) != 32 {
				slog.Error("invalid wireguard public key", "key", allow)
				continue
			}
			slog.Info("adding allowed public key", "key", allow)
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
				slog.Debug("fsnotify event", "event", event)
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Write) {
					readAllowKeys(allowFile)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("fsnotify error", "error", err)
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
