// Package openp2p builds the join-side configuration for the openp2p engine.
//
// Role split (verified against openp2p-cn/openp2p master):
//
//   - The **phone** hosts the WebDAV server and is the *server* side of the
//     tunnel. It needs no forwarding command at all — it only runs the engine
//     and logs in. When the PC creates the tunnel it pushes
//     MsgPushServerSideSaveMemApp and the server side builds the app itself
//     (core/handlepush.go), then dials DstHost:DstPort locally
//     (core/p2ptunnel.go handleOverlayConnectReq).
//   - The **PC** is the *client*: it listens on 127.0.0.1:SrcPort and initiates
//     the tunnel (core/p2papp.go Start(true) → buildDirectTunnel).
//
// So the only command this package has to produce is the PC side:
//
//	openp2p -nv -newconfig -node otg-<id> -token <n> -peernode <phone node> \
//	        -srcport <local> -dstip 127.0.0.1 -dstport 8080 -protocol tcp \
//	        -sharebandwidth 0 -serverhost api.openp2p.cn -serverport 27183
//
// Namespace discipline — this is the user's constraint, not a style choice.
// The machine already runs two deployments that must not be disturbed:
//
//	aliyun-qingdao-<suffix>   the openp2p system service on the ECS
//	ecs-<roomId>              one forwarder per o2p-platform room
//
// This package only ever generates names under "otg-", and [Validate] rejects
// the reserved prefixes outright, so a caller cannot accidentally join the
// existing namespace even by passing its own name. Nothing here reads or writes
// the existing config.json files: [ConfigJSON] is for a fresh, isolated
// directory that the caller owns.
package openp2p

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	// NodePrefix is the namespace this project owns.
	NodePrefix = "otg-"

	// MinNodeNameLen is the engine's own lower bound (core/common.go).
	MinNodeNameLen = 8

	// MaxNodeNameLen comes from the -node flag help text ("8-31 characters").
	MaxNodeNameLen = 31

	// DefaultServerHost / DefaultServerPort are the engine's public defaults.
	// 27183 is the WsPort the existing deployments use; keep them in sync so a
	// new node talks to the same gateway.
	DefaultServerHost = "api.openp2p.cn"
	DefaultServerPort = 27183
)

// reservedPrefixes belong to deployments that must not be touched. A node name
// starting with one of these is rejected in [Validate].
var reservedPrefixes = []string{"ecs-", "aliyun-"}

// Network mirrors core.NetworkConfig. Only the fields a fresh client needs are
// modelled; the engine fills the rest at login and saves them back.
type Network struct {
	Token          uint64
	Node           string
	ShareBandwidth int
	ServerHost     string
	ServerPort     int
}

// App mirrors the exported half of core.AppConfig. Field names are the JSON
// keys the engine uses (the upstream struct has no tags, so the Go field names
// are the wire names).
type App struct {
	AppName  string
	Protocol string
	SrcPort  int
	PeerNode string
	DstPort  int
	DstHost  string
	Enabled  int
}

// Config is a minimal, self-contained config.json for an isolated run. The
// engine's Config has more fields (LogLevel, MaxLogSize, …); the zero values
// are valid and the engine rewrites the file after login.
type Config struct {
	Network Network `json:"network"`
	Apps    []App   `json:"apps"`
}

// JoinOptions describe the PC side of one tunnel to the phone.
type JoinOptions struct {
	// Node is this PC's node name. Empty means "generate one" in [Args].
	Node string

	// Token is the numeric openp2p token (the CLI flag is a uint64; a string
	// would be parsed as 0 and the login silently fails — a real incident on
	// the ECS, see the project notes).
	Token uint64

	// PeerNode is the phone's **effective** node name. The engine may rewrite
	// a node name at login (core/p2pnetwork.go: `if len(rsp.Node) >=
	// MinNodeNameLen { gConf.setNode(rsp.Node) }`), which is why the phone has
	// to publish what it actually got (Android: Openp2p.getAndroidNodeName())
	// rather than what was configured.
	PeerNode string

	// SrcPort is the local port on the PC; the WebDAV client dials
	// http://127.0.0.1:SrcPort/.
	SrcPort int

	// DstHost/DstPort are resolved **on the phone**: 127.0.0.1:8080 is the
	// WebDAV listener there.
	DstHost string
	DstPort int

	// Protocol is "tcp" (the WebDAV case) or "udp".
	Protocol string

	ServerHost string
	ServerPort int
}

// NewNodeName returns a fresh name in this project's namespace: "otg-" plus
// eight hex characters (12 chars total, inside the engine's 8..31 window).
func NewNodeName() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not a recoverable condition for a name
		// generator; fall back to a fixed suffix rather than panic, and let
		// Validate (length/charset) still hold.
		return NodePrefix + "00000000"
	}
	return NodePrefix + hex.EncodeToString(b)
}

// Reserved reports whether name belongs to a deployment that must not be
// touched (the ECS service node or an o2p-platform room).
func Reserved(name string) bool {
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Validate checks everything the engine would otherwise accept silently or
// reject with an opaque login error.
func (o JoinOptions) Validate() error {
	if o.Token == 0 {
		return errors.New("openp2p: token must be a non-zero uint64 (a string token parses as 0)")
	}
	if err := validateNodeName(o.Node, "node"); err != nil {
		return err
	}
	if o.PeerNode == "" {
		return errors.New("openp2p: peernode is required (the phone's effective node name)")
	}
	if Reserved(o.PeerNode) {
		return fmt.Errorf("openp2p: peernode %q is in a reserved namespace", o.PeerNode)
	}
	if len(o.PeerNode) < MinNodeNameLen || len(o.PeerNode) > MaxNodeNameLen {
		return fmt.Errorf("openp2p: peernode %q must be %d-%d characters", o.PeerNode, MinNodeNameLen, MaxNodeNameLen)
	}
	if o.SrcPort < 1024 || o.SrcPort > 65535 {
		return fmt.Errorf("openp2p: srcport %d out of range (1024-65535)", o.SrcPort)
	}
	if o.DstPort < 1 || o.DstPort > 65535 {
		return fmt.Errorf("openp2p: dstport %d out of range (1-65535)", o.DstPort)
	}
	proto := strings.ToLower(o.Protocol)
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("openp2p: protocol %q must be tcp or udp", o.Protocol)
	}
	if o.DstHost == "" {
		return errors.New("openp2p: dsthost is required (127.0.0.1 for the phone's WebDAV)")
	}
	return nil
}

func validateNodeName(name, field string) error {
	if name == "" {
		return fmt.Errorf("openp2p: %s is required", field)
	}
	if len(name) < MinNodeNameLen || len(name) > MaxNodeNameLen {
		return fmt.Errorf("openp2p: %s %q must be %d-%d characters", field, name, MinNodeNameLen, MaxNodeNameLen)
	}
	if Reserved(name) {
		return fmt.Errorf("openp2p: %s %q is in a reserved namespace (ecs-/aliyun-)", field, name)
	}
	for _, r := range name {
		ok := r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("openp2p: %s %q contains an unsupported character %q", field, name, r)
		}
	}
	return nil
}

// Args renders the PC-side command line. `-dstip`, not `-dsthost`: the engine's
// flag is named dstip (core/config.go parseParams), and passing the wrong one
// leaves the default 127.0.0.1 in place without an error.
func (o JoinOptions) Args(openp2pPath string) ([]string, error) {
	if openp2pPath == "" {
		openp2pPath = "openp2p"
	}
	if o.Node == "" {
		o.Node = NewNodeName()
	}
	if o.DstHost == "" {
		o.DstHost = "127.0.0.1"
	}
	if o.Protocol == "" {
		o.Protocol = "tcp"
	}
	if o.ServerHost == "" {
		o.ServerHost = DefaultServerHost
	}
	if o.ServerPort == 0 {
		o.ServerPort = DefaultServerPort
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	// One flag per line on purpose: the argv is the contract with the engine,
	// and a diff that moves a flag is easier to read than one that reflows a
	// packed literal.
	return []string{
		openp2pPath,
		"-nv",
		"-newconfig",
		"-node", o.Node,
		"-token", fmt.Sprintf("%d", o.Token),
		"-peernode", o.PeerNode,
		"-srcport", fmt.Sprintf("%d", o.SrcPort),
		"-dstip", o.DstHost,
		"-dstport", fmt.Sprintf("%d", o.DstPort),
		"-protocol", strings.ToLower(o.Protocol),
		"-sharebandwidth", "0",
		"-serverhost", o.ServerHost,
		"-serverport", fmt.Sprintf("%d", o.ServerPort),
	}, nil
}

// ConfigJSON renders an equivalent config.json for an isolated run directory.
// Callers that pass all flags do not need it; it exists so a future daemon can
// restart from the same file without rebuilding argv.
func (o JoinOptions) ConfigJSON() ([]byte, error) {
	if o.Node == "" {
		o.Node = NewNodeName()
	}
	if o.DstHost == "" {
		o.DstHost = "127.0.0.1"
	}
	if o.Protocol == "" {
		o.Protocol = "tcp"
	}
	if o.ServerHost == "" {
		o.ServerHost = DefaultServerHost
	}
	if o.ServerPort == 0 {
		o.ServerPort = DefaultServerPort
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	cfg := Config{
		Network: Network{
			Token:          o.Token,
			Node:           o.Node,
			ShareBandwidth: 0,
			ServerHost:     o.ServerHost,
			ServerPort:     o.ServerPort,
		},
		Apps: []App{{
			AppName:  "webdav",
			Protocol: strings.ToLower(o.Protocol),
			SrcPort:  o.SrcPort,
			PeerNode: o.PeerNode,
			DstPort:  o.DstPort,
			DstHost:  o.DstHost,
			Enabled:  1,
		}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// ParseLogin extracts the effective node name from the engine's log line
//
//	login ok. user=<user>, node=<node>
//
// The name in that line is the one the server assigned, which can differ from
// the configured one. The PC uses it for its own bookkeeping; the phone must
// publish it for peers to target.
func ParseLogin(line string) (user, node string, ok bool) {
	const marker = "login ok. user="
	i := strings.Index(line, marker)
	if i < 0 {
		return "", "", false
	}
	rest := line[i+len(marker):]
	parts := strings.SplitN(rest, ", node=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	user = strings.TrimSpace(parts[0])
	node = strings.TrimSpace(parts[1])
	if user == "" || node == "" {
		return "", "", false
	}
	return user, node, true
}

// FreeLocalPort asks the OS for an unused loopback port. Used to pick SrcPort
// without guessing a value that may already be taken.
func FreeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
