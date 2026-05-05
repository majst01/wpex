package watcher

import (
	"encoding/base64"
	"io/fs"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

func CreateAllowDirWatcher(allowDir string) (func() [][]byte, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	slog.Info("listening for allowed public keys", "allow-dir", allowDir)

	var allowKeys atomic.Value

	readAllowKeys := func(dir string) {

		root, err := os.OpenRoot(dir)
		if err != nil {
			slog.Error("unable to read root directory", "error", err)
			return
		}

		files, err := fs.Glob(root.FS(), "*")
		if err != nil {
			slog.Error("unable to read files in root directory", "error", err)
			return
		}

		var tempAllows [][]byte
		for _, f := range files {
			info, err := root.Stat(f)
			if err != nil {
				slog.Error("unable to stat file", "file", f, "error", err)
				continue
			}

			if info.IsDir() {
				continue
			}

			if info.Size() == 0 {
				continue
			}

			content, err := root.ReadFile(f)
			if err != nil {
				slog.Error("unable to read allow file", "file", f, "error", err)
				continue
			}
			k, err := base64.StdEncoding.DecodeString(string(content))
			if err != nil || len(k) != 32 {
				slog.Error("invalid wireguard public key", "file", f, "key", content)
				continue
			}
			slog.Info("adding allowed public key", "file", f, "key", content)
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
					readAllowKeys(allowDir)
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

	readAllowKeys(allowDir)

	return func() [][]byte {
		return allowKeys.Load().([][]byte)
	}, nil
}
