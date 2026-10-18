//go:build windows

package davfs

import (
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jingjiangze/Otg-drive-bridge/windows/internal/webdavclient"
	"github.com/winfsp/go-winfsp/gofs"
)

// FS exposes one WebDAV endpoint as a Windows file system.
//
// Hydration is the core design decision, forced by two verified facts:
// gofs.File demands random access (ReadAt/WriteAt/Seek/Truncate —
// gofs/gofs_windows.go's interface), while WebDAV has no random-write verb.
// So opening a file GETs it into a local temp, every Windows operation runs
// against that temp (via the embedded *os.File, which already satisfies the
// whole gofs.File method set — memfs' own test `var _ gofs.File = (*os.File)`
// style), and Close PUTs it back. The phone's server commits PUTs atomically
// (staging file → rename), so a killed upload cannot corrupt the real file.
type FS struct {
	srv *webdavclient.Server
}

var _ gofs.FileSystem = (*FS)(nil)

func NewFS(srv *webdavclient.Server) *FS { return &FS{srv: srv} }

// statHref is a depth-0 PROPFIND. (nil, nil) means "does not exist" — the
// 404 case, so callers can distinguish "missing" from "server said no".
func (f *FS) statHref(ctx context.Context, href string) (*webdavclient.Node, error) {
	nodes, err := f.srv.Propfind(ctx, href, "0")
	if err != nil {
		if webdavclient.Code(err) == 404 {
			return nil, nil
		}
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	return &nodes[0], nil
}

func (f *FS) OpenFile(name string, flag int, _ os.FileMode) (gofs.File, error) {
	ctx := context.Background()
	segs := Segments(name)
	href := Href(segs)
	node, err := f.statHref(ctx, href)
	if err != nil {
		return nil, err
	}

	if node != nil && node.IsDir {
		if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND) != 0 {
			return nil, syscall.EISDIR
		}
		return &dirFile{fs: f, href: href}, nil
	}
	if node != nil && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0 {
		// FILE_CREATE semantics (only meaningful with O_CREATE): Windows
		// expects the create to fail loudly when the resource already exists.
		// Ignoring O_EXCL would silently turn every create-new into an
		// overwrite.
		return nil, os.ErrExist
	}
	if node == nil && flag&os.O_CREATE == 0 {
		return nil, os.ErrNotExist
	}

	// Hydrate an existing file, or start an empty temp for a create.
	temp, err := os.CreateTemp("", "otg-davfs-")
	if err != nil {
		return nil, err
	}
	fail := func(e error) (gofs.File, error) {
		temp.Close()
		os.Remove(temp.Name())
		return nil, e
	}
	if node != nil {
		body, _, _, err := f.srv.Get(ctx, href)
		if err != nil {
			return fail(err)
		}
		_, cerr := io.Copy(temp, body)
		body.Close()
		if cerr != nil {
			return fail(cerr)
		}
	}
	if flag&os.O_TRUNC != 0 {
		if err := temp.Truncate(0); err != nil {
			return fail(err)
		}
	}

	// A brand-new resource must always commit on close, even for a
	// read-flavoured open: without this, `O_CREATE|O_RDONLY` opened a file,
	// dropped the temp and PUT nothing — the create silently vanished.
	// Existing files commit only when the open asked to write; a read-only
	// open never uploads. A file opened read-write but never written is still
	// re-PUT: the bytes are identical, and a conditional PUT would fight with
	// hydration semantics of an open handle. Same trade rclone mount makes.
	writeIntent := node == nil || flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0
	var info os.FileInfo = &nodeInfo{name: lastName(segs), mode: 0o644, modTime: time.Now()}
	if node != nil {
		info = NodeToFileInfo(*node)
	}
	return &fileHandle{
		File:        temp,
		tempPath:    temp.Name(),
		fs:          f,
		href:        href,
		info:        info,
		writeIntent: writeIntent,
	}, nil
}

func (f *FS) Mkdir(name string, _ os.FileMode) error {
	href := Href(Segments(name))
	resp, err := f.srv.Mkcol(context.Background(), href)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200, 201, 204:
		return nil
	case 405:
		// RFC 4918 §9.3.2: MKCOL on an existing resource is 405 — gofs maps
		// os.ErrExist onto STATUS_OBJECT_NAME_COLLISION, which is exactly the
		// "already exists" answer Windows wants.
		return os.ErrExist
	case 409:
		return os.ErrNotExist // parent collection missing
	default:
		return &os.PathError{Op: "mkdir", Path: name, Err: syscall.EIO}
	}
}

func (f *FS) Stat(name string) (os.FileInfo, error) {
	node, err := f.statHref(context.Background(), Href(Segments(name)))
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, os.ErrNotExist
	}
	return NodeToFileInfo(*node), nil
}

func (f *FS) Rename(source, target string) error {
	ctx := context.Background()
	src := Href(Segments(source))
	dst := Href(Segments(target))
	resp, err := f.srv.MoveOrCopy(ctx, "MOVE", src, dst, true, webdavclient.DestAbsolute)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 201, 204:
		return nil
	case 404:
		return os.ErrNotExist
	case 409:
		return os.ErrNotExist // destination parent missing
	case 423:
		return syscall.EBUSY
	default:
		return &os.PathError{Op: "rename", Path: source, Err: syscall.EIO}
	}
}

func (f *FS) Remove(name string) error {
	ctx := context.Background()
	href := Href(Segments(name))
	node, err := f.statHref(ctx, href)
	if err != nil {
		return err
	}
	if node == nil {
		return os.ErrNotExist
	}
	// The phone's DELETE is recursive (FileSystemDavStorage.delete →
	// deleteRecursively), which the Windows semantics do NOT want from
	// RemoveFile: os.Remove must fail on a non-empty directory, otherwise a
	// program that expects ENOTEMPTY silently destroys a tree. So enforce it
	// client-side — matching passthrough's os.Remove behaviour, which gofs is
	// written against.
	if node.IsDir {
		nodes, err := f.srv.Propfind(ctx, href, "1")
		if err != nil {
			return err
		}
		self := strings.TrimSuffix(DecodeHref(href), "/")
		for _, n := range nodes {
			h := strings.TrimSuffix(DecodeHref(n.Href), "/")
			if h == self || h == "" {
				continue
			}
			return syscall.ENOTEMPTY
		}
	}
	resp, err := f.srv.Delete(ctx, href)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200, 204:
		return nil
	case 404:
		return os.ErrNotExist
	case 423:
		return syscall.EBUSY
	default:
		return &os.PathError{Op: "remove", Path: name, Err: syscall.EIO}
	}
}

// fileHandle is a hydrated file: the embedded *os.File answers every byte-level
// gofs.File method; only OpenFile plumbing, Stat and the commit-on-Close are
// ours.
type fileHandle struct {
	*os.File
	tempPath    string
	fs          *FS
	href        string
	info        os.FileInfo
	writeIntent bool
}

func (h *fileHandle) Stat() (os.FileInfo, error) {
	st, err := h.File.Stat()
	if err != nil {
		return nil, err
	}
	return &nodeInfo{
		name:    h.info.Name(),
		size:    st.Size(),
		mode:    h.info.Mode(),
		modTime: h.info.ModTime(),
	}, nil
}

func (h *fileHandle) Close() error {
	if h.File == nil {
		return nil
	}
	if err := h.File.Close(); err != nil {
		return err
	}
	h.File = nil
	if !h.writeIntent {
		// Read-only open: drop the cache copy.
		return os.Remove(h.tempPath)
	}
	f, err := os.Open(h.tempPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	// PutStream needs a completed Digest handshake; the hydration GET (or the
	// empty-file path's Stat PROPFIND) always recorded one before we get here.
	if _, err := h.fs.srv.PutStream(context.Background(), h.href, f, st.Size()); err != nil {
		return err
	}
	return os.Remove(h.tempPath)
}

func lastName(segs []string) string {
	if len(segs) == 0 {
		return "/"
	}
	return segs[len(segs)-1]
}
