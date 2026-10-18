// Command otg-mount exposes an OTG Drive Bridge WebDAV share as a Windows
// drive letter through WinFSP.
//
// The remote path matters for credentials: an openp2p tunnel arrives at the
// phone as a connection from the phone's own 127.0.0.1 (the engine dials the
// local port on the phone side), so the LAN passkey — deliberately not
// trusted over loopback — will not authenticate through it. Use the primary
// account, or issue a temporary key on the phone and let it expire after the
// session.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jingjiangze/Otg-drive-bridge/windows/davfs"
	"github.com/jingjiangze/Otg-drive-bridge/windows/internal/webdavclient"
	"github.com/winfsp/go-winfsp"
	"github.com/winfsp/go-winfsp/gofs"
)

func main() {
	log.SetFlags(log.Ltime)
	if err := run(); err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		url   = flag.String("url", "http://127.0.0.1:8080/", "WebDAV endpoint (an openp2p forward lands here)")
		user  = flag.String("user", "", "WebDAV username (primary account; see the package doc about the LAN passkey)")
		pass  = flag.String("pass", "", "WebDAV password")
		realm = flag.String("realm", "OTG Drive Bridge", "Digest realm; must match the phone")
		mount = flag.String("mount", "Z:", "drive letter to mount on")
	)
	flag.Parse()

	if *user == "" || *pass == "" {
		return errors.New("-user and -pass are required")
	}
	srv := webdavclient.New(*url, *user, *pass, *realm)

	// Probe is the handshake and the sanity check: OPTIONS itself is
	// unauthenticated, but the client records the realm from the first 401 it
	// answers, and PutStream refuses to upload before that handshake exists.
	// Probing also fails early and legibly when the URL points at something
	// that is not this server — a tunnel that never came up, say.
	if err := srv.Probe(context.Background()); err != nil {
		return fmt.Errorf("probe %s: %w (is the tunnel up? wrong realm?)", *url, err)
	}

	fs := davfs.NewFS(srv)

	// Mount returns an error when WinFSP is not installed — no panic on this
	// path — and the message names the DLL that failed to load.
	mnt, err := winfsp.Mount(gofs.New(fs), *mount)
	if err != nil {
		return fmt.Errorf("mount %s: %w (WinFSP installed?)", *mount, err)
	}
	log.Printf("mounted %s -> %s; Ctrl+C to unmount", *mount, *url)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	// Unmount is mandatory: without it the dispatcher thread dies with the
	// process while Windows keeps the drive letter visible and disconnected.
	mnt.Unmount()
	log.Printf("unmounted %s", *mount)
	return nil
}
