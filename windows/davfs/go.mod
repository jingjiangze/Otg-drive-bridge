module github.com/jingjiangze/Otg-drive-bridge/windows/davfs

go 1.25

require (
	github.com/jingjiangze/Otg-drive-bridge/windows v0.0.0-00010101000000-000000000000
	github.com/winfsp/go-winfsp v1.0.6
)

// The parent module is consumed by path, not by version: it is never published,
// and this module lives inside its directory. `replace` with a relative path is
// exactly how go-winfsp's own examples/passthrough consumes its parent.
replace github.com/jingjiangze/Otg-drive-bridge/windows => ../
