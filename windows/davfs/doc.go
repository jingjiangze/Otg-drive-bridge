// Package davfs adapts the WebDAV client to a Windows drive letter through
// go-winfsp.
//
// Two constraints shape the design, and both were verified against sources
// rather than assumed:
//
//   - gofs.File demands random access (ReadAt/WriteAt/Seek/Truncate), but
//     WebDAV has no random-write verb — PUT replaces the whole resource. So a
//     file is *hydrated*: GET into a local temp file on open, every Windows
//     operation runs against that temp, and Close puts it back. The phone's
//     server commits a PUT atomically (staging tmp → rename), so a partial
//     upload can never corrupt the real file.
//   - gofs hands names to FileSystem as unified Windows paths: root is `""`
//     or `"\"`, members look like `\docs\a.txt`. The helpers here translate
//     that into the client's percent-encoded hrefs.
//
// This file is build-tagged windows-only because it imports gofs; the pure
// pieces (paths, node → FileInfo) live in paths.go with no tag, so the Linux
// CI can still unit-test them.
package davfs
