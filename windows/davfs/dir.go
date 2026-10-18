//go:build windows

package davfs

import (
	"context"
	"os"
	"strings"
	"syscall"
)

// dirFile answers a directory open. Byte-level methods return EISDIR the way
// passthrough's os.File does on a directory handle, and Readdir runs a depth-1
// PROPFIND. gofs reopens directories with handle.flags, which is always
// O_RDONLY for something that resolved to a directory, so Read/Write never
// actually run.
type dirFile struct {
	fs   *FS
	href string
}

func (d *dirFile) Read([]byte) (int, error) {
	return 0, syscall.EISDIR
}

func (d *dirFile) Write([]byte) (int, error) {
	return 0, syscall.EISDIR
}

func (d *dirFile) Seek(int64, int) (int64, error) {
	return 0, syscall.EISDIR
}

func (d *dirFile) ReadAt([]byte, int64) (int, error) {
	return 0, syscall.EISDIR
}

func (d *dirFile) WriteAt([]byte, int64) (int, error) {
	return 0, syscall.EISDIR
}

func (d *dirFile) Truncate(int64) error {
	return syscall.EISDIR
}

func (d *dirFile) Sync() error { return nil }

func (d *dirFile) Close() error { return nil }

func (d *dirFile) Stat() (os.FileInfo, error) {
	node, err := d.fs.statHref(context.Background(), d.href)
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, os.ErrNotExist
	}
	return NodeToFileInfo(*node), nil
}

// Readdir lists children, skipping the self entry a depth-1 PROPFIND always
// includes: WebDavRequestHandler emits collection + children (RFC 4918 §14.2),
// while memfs — the reference gofs.FileSystem — stores children only. Passing
// the self entry through would show the directory inside its own listing.
func (d *dirFile) Readdir(count int) ([]os.FileInfo, error) {
	nodes, err := d.fs.srv.Propfind(context.Background(), d.href, "1")
	if err != nil {
		return nil, err
	}
	self := strings.TrimSuffix(DecodeHref(d.href), "/")
	var out []os.FileInfo
	for _, n := range nodes {
		if strings.TrimSuffix(DecodeHref(n.Href), "/") == self {
			continue
		}
		out = append(out, NodeToFileInfo(n))
	}
	if count > 0 && len(out) > count {
		return out[:count], nil
	}
	return out, nil
}
