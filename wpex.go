package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/weiiwang01/wpex/internal/relay"
	"github.com/weiiwang01/wpex/internal/watcher"
	"golang.org/x/time/rate"
)

var version string

type pubKeys []string

func (ks *pubKeys) String() string {
	return strings.Join(*ks, ",")
}

func (ks *pubKeys) Set(s string) error {
	*ks = append(*ks, s)
	return nil
}

func main() {
	bind := flag.String("bind", "", "address to bind to")
	port := flag.Uint("port", 40000, "port number to listen")
	debug := flag.Bool("debug", false, "enable debug messages")
	broadcastRate := flag.Uint("broadcast-rate", 0, "broadcast rate limit in packet per second")
	versionFlag := flag.Bool("version", false, "show version number and quit")
	allowFile := flag.String("allow-file", "", "file which contains a wireguard public key per line. Must not be specified together with --allow")

	var allows pubKeys
	flag.Var(&allows, "allow", "allow a wireguard public key. --allow can be used multiple times for allowing multiple public keys")

	flag.Parse()
	if *versionFlag {
		fmt.Println("wpex", version)
		os.Exit(0)
	}

	loggingLevel := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: loggingLevel}))
	if *debug {
		loggingLevel.Set(slog.LevelDebug)
	}
	slog.SetDefault(logger)

	if len(allows) > 0 && allowFile != nil && len(*allowFile) > 0 {
		log.Fatalf("you must not specify --allow and --allow-file")
	}

	var allowKeys [][]byte
	for _, allow := range allows {
		k, err := base64.StdEncoding.DecodeString(allow)
		if err != nil || len(k) != 32 {
			log.Fatalf("invalid wireguard public key: '%s'", allow)
		}
		logger.Debug("allow wireguard public key", "key", allow)
		allowKeys = append(allowKeys, k)
	}

	publicKeysFunc := func() [][]byte {
		return allowKeys
	}

	if allowFile != nil && len(*allowFile) > 0 {
		if _, err := os.Stat(*allowFile); err == nil {
			publicKeysFunc, err = watcher.CreateAllowDirWatcher(*allowFile)
			if err != nil {
				log.Fatalf("unable to create a allow-file watcher:%v", err)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			log.Fatalf("given allow-file does not exist:%v", err)
		} else {
			log.Fatalf("error reading allow-file:%v", err)
		}
	}

	limit := rate.Limit(*broadcastRate)
	if *broadcastRate == 0 {
		slog.Debug("broadcast rate limit is set to +Inf")
		limit = rate.Inf
	} else {
		slog.Debug("broadcast rate limit is set to", "rate", *broadcastRate)
	}

	address := fmt.Sprintf("%s:%d", *bind, *port)
	relay.Start(address, publicKeysFunc, rate.NewLimiter(limit, int((*broadcastRate)*5)))
}
