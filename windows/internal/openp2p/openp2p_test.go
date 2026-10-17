package openp2p

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewNodeNameStaysInOurNamespace(t *testing.T) {
	seen := make(map[string]bool, 512)
	for i := 0; i < 512; i++ {
		name := NewNodeName()
		if !strings.HasPrefix(name, NodePrefix) {
			t.Fatalf("name %q is outside the %q namespace", name, NodePrefix)
		}
		if len(name) < MinNodeNameLen || len(name) > MaxNodeNameLen {
			t.Fatalf("name %q length %d outside %d-%d", name, len(name), MinNodeNameLen, MaxNodeNameLen)
		}
		if Reserved(name) {
			t.Fatalf("generated a reserved name %q", name)
		}
		if seen[name] {
			t.Fatalf("duplicate name %q after %d draws", name, i)
		}
		seen[name] = true
	}
}

func TestValidateRejectsTheExistingDeployments(t *testing.T) {
	base := JoinOptions{
		Node:     "otg-1234abcd",
		Token:    42,
		PeerNode: "otg-phone01",
		SrcPort:  18080,
		DstHost:  "127.0.0.1",
		DstPort:  8080,
		Protocol: "tcp",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline should validate: %v", err)
	}

	cases := []struct {
		name string
		mut  func(o *JoinOptions)
		want string
	}{
		{"ecs room node", func(o *JoinOptions) { o.Node = "ecs-000400e4" }, "reserved"},
		{"ecs peer", func(o *JoinOptions) { o.PeerNode = "ecs-000400e4" }, "reserved"},
		{"aliyun service node", func(o *JoinOptions) { o.Node = "aliyun-qingdao-vStm8ntS" }, "reserved"},
		{"zero token", func(o *JoinOptions) { o.Token = 0 }, "token"},
		{"short node", func(o *JoinOptions) { o.Node = "otg-1" }, "characters"},
		{"long peer", func(o *JoinOptions) { o.PeerNode = strings.Repeat("a", MaxNodeNameLen+1) }, "characters"},
		{"bad char", func(o *JoinOptions) { o.Node = "otg-bad name!" }, "unsupported character"},
		{"srcport low", func(o *JoinOptions) { o.SrcPort = 80 }, "srcport"},
		{"dstport high", func(o *JoinOptions) { o.DstPort = 70000 }, "dstport"},
		{"bad protocol", func(o *JoinOptions) { o.Protocol = "sctp" }, "protocol"},
		{"no peer", func(o *JoinOptions) { o.PeerNode = "" }, "peernode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := base
			c.mut(&o)
			err := o.Validate()
			if err == nil {
				t.Fatalf("expected an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestArgsUseDstipNotDsthost(t *testing.T) {
	o := JoinOptions{
		Node:     "otg-1234abcd",
		Token:    1234567890123456789,
		PeerNode: "otg-phone01",
		SrcPort:  18080,
		DstHost:  "127.0.0.1",
		DstPort:  8080,
		Protocol: "tcp",
	}
	args, err := o.Args("openp2p.exe")
	if err != nil {
		t.Fatalf("Args: %v", err)
	}
	joined := strings.Join(args, " ")

	// The engine's flag is -dstip; -dsthost is silently ignored and the
	// default 127.0.0.1 stays in place, which looks like a working tunnel.
	if strings.Contains(joined, "-dsthost") {
		t.Fatalf("argv contains -dsthost, which the engine does not define: %s", joined)
	}
	want := []string{
		"openp2p.exe", "-nv", "-newconfig",
		"-node", "otg-1234abcd",
		"-token", "1234567890123456789",
		"-peernode", "otg-phone01",
		"-srcport", "18080",
		"-dstip", "127.0.0.1",
		"-dstport", "8080",
		"-protocol", "tcp",
		"-sharebandwidth", "0",
		"-serverhost", DefaultServerHost,
		"-serverport", "27183",
	}
	if len(args) != len(want) {
		t.Fatalf("argv length %d, want %d: %v", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: %v)", i, args[i], want[i], args)
		}
	}
}

func TestArgsFillDefaults(t *testing.T) {
	o := JoinOptions{
		Token:    7,
		PeerNode: "otg-phone01",
		SrcPort:  18080,
		DstPort:  8080,
	}
	args, err := o.Args("")
	if err != nil {
		t.Fatalf("Args: %v", err)
	}
	if args[0] != "openp2p" {
		t.Fatalf("default binary = %q, want openp2p", args[0])
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-node otg-",
		"-dstip 127.0.0.1",
		"-protocol tcp",
		"-serverhost " + DefaultServerHost,
		"-serverport 27183",
		"-sharebandwidth 0",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %s", want, joined)
		}
	}
}

func TestConfigJSONShape(t *testing.T) {
	o := JoinOptions{
		Node:     "otg-1234abcd",
		Token:    99,
		PeerNode: "otg-phone01",
		SrcPort:  18080,
		DstHost:  "127.0.0.1",
		DstPort:  8080,
		Protocol: "tcp",
	}
	raw, err := o.ConfigJSON()
	if err != nil {
		t.Fatalf("ConfigJSON: %v", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	network, ok := generic["network"].(map[string]any)
	if !ok {
		t.Fatalf("missing network object: %s", raw)
	}
	// The engine's Token is a uint64 on the wire; a JSON string would parse as
	// 0 and the login would silently fail.
	if _, ok := network["Token"].(float64); !ok {
		t.Fatalf("network.Token must be a JSON number, got %T: %s", network["Token"], raw)
	}
	if network["Node"] != "otg-1234abcd" {
		t.Fatalf("network.Node = %v", network["Node"])
	}
	apps, ok := generic["apps"].([]any)
	if !ok || len(apps) != 1 {
		t.Fatalf("expected one app: %s", raw)
	}
	app := apps[0].(map[string]any)
	if app["PeerNode"] != "otg-phone01" || app["SrcPort"].(float64) != 18080 {
		t.Fatalf("app fields wrong: %v", app)
	}
	if app["Enabled"].(float64) != 1 {
		t.Fatalf("Enabled must be the integer 1 (the engine's field is an int): %v", app["Enabled"])
	}
}

func TestParseLoginReadsTheAssignedName(t *testing.T) {
	// A real line from the ECS service: the configured name was
	// "aliyun-qingdao" and the server appended a suffix.
	user, node, ok := ParseLogin("2026-10-15 10:00:00 login ok. user=jingjiangze, node=aliyun-qingdao-vStm8ntS")
	if !ok || user != "jingjiangze" || node != "aliyun-qingdao-vStm8ntS" {
		t.Fatalf("ParseLogin = (%q,%q,%v)", user, node, ok)
	}
	for _, bad := range []string{"", "hello", "login error:600", "login ok. user=x"} {
		if _, _, ok := ParseLogin(bad); ok {
			t.Fatalf("%q should not parse", bad)
		}
	}
}

func TestFreeLocalPort(t *testing.T) {
	port, err := FreeLocalPort()
	if err != nil {
		t.Fatalf("FreeLocalPort: %v", err)
	}
	if port < 1024 || port > 65535 {
		t.Fatalf("port %d out of range", port)
	}
}
