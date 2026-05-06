package watcher

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

type endpoint struct {
	PublicKey string `json:"publicKey"`
	ForwardTo string `json:"forwardTo,omitempty"`
}

func CreateAllowDirWatcher(allowDir string) (func() [][]byte, func() []net.UDPAddr, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, err
	}

	slog.Info("listening for allowed public keys", "allow-dir", allowDir)

	var (
		allowKeys           atomic.Value
		additionalAddresses atomic.Value
	)

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

		var (
			tempAllows              [][]byte
			tempAdditionalAddresses []net.UDPAddr
		)

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

			var ep endpoint
			if err := json.Unmarshal(content, &ep); err != nil {
				slog.Error("unable to unmarshal allow file content", "file", f, "content", string(content), "error", err)
				continue
			}

			if len(ep.ForwardTo) > 0 {
				addr, err := netip.ParseAddrPort(ep.ForwardTo)
				if err != nil {
					slog.Error("unable to parse forward-to", "forward-to", ep.ForwardTo, "error", err)
					continue
				}
				slog.Info("adding forward-to address to additional addresses", "forward-to", addr)
				tempAdditionalAddresses = append(tempAdditionalAddresses, *net.UDPAddrFromAddrPort(addr))
			}

			k, err := base64.StdEncoding.DecodeString(ep.PublicKey)
			if err != nil || len(k) != 32 {
				slog.Error("invalid wireguard public key", "file", f, "key", content)
				continue
			}
			slog.Info("adding allowed public key", "file", f, "key", content)
			tempAllows = append(tempAllows, k)
		}
		allowKeys.Store(tempAllows)
		additionalAddresses.Store(tempAdditionalAddresses)
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
		return nil, nil, err
	}

	readAllowKeys(allowDir)

	return func() [][]byte {
			return allowKeys.Load().([][]byte)
		}, func() []net.UDPAddr {
			return additionalAddresses.Load().([]net.UDPAddr)
		}, nil
}
