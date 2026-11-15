package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func buildArgs(t *testing.T, goos string, input ...string) invocation {
	t.Helper()
	result, err := buildForOS(goos, input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTerminalUsesStrictHostVerification(t *testing.T) {
	inv := buildArgs(t, "linux", "terminal", "--host", "dev.lan", "--user", "jack", "--port", "2222")
	want := []string{"-F", "none", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", "-p", "2222", "-l", "jack", "--", "dev.lan"}
	if inv.program != "ssh" || !reflect.DeepEqual(inv.args, want) {
		t.Fatalf("unexpected invocation: %+v", inv)
	}
}

func TestFilesAndCheckUseExistingKeys(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	known := filepath.Join(dir, "known_hosts")
	for _, path := range []string{key, known} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	common := []string{"--host", "2001:db8::1", "--user", "dev", "--identity", key, "--known-hosts", known}
	files := buildArgs(t, "linux", append([]string{"files"}, common...)...)
	if files.program != "sftp" || files.args[len(files.args)-1] != "dev@[2001:db8::1]" || files.args[len(files.args)-3] != "22" {
		t.Fatalf("unexpected sftp: %+v", files)
	}
	check := buildArgs(t, "linux", append([]string{"check"}, common...)...)
	if check.program != "ssh" || check.args[len(check.args)-1] != "true" || !strings.Contains(strings.Join(check.args, " "), "BatchMode=yes") {
		t.Fatalf("unexpected check: %+v", check)
	}
}

func TestDesktopUsesNativeWindowsClient(t *testing.T) {
	inv := buildArgs(t, "windows", "desktop", "--host", "192.0.2.8")
	if inv.program != "mstsc.exe" || !reflect.DeepEqual(inv.args, []string{"/v:192.0.2.8:3389"}) {
		t.Fatalf("unexpected RDP invocation: %+v", inv)
	}
	inv = buildArgs(t, "windows", "desktop", "--host", "2001:db8::2", "--port", "3390")
	if !reflect.DeepEqual(inv.args, []string{"/v:[2001:db8::2]:3390"}) {
		t.Fatalf("unexpected IPv6 RDP invocation: %+v", inv)
	}
	if _, err := buildForOS("linux", []string{"desktop", "--host", "dev.lan"}); err == nil {
		t.Fatal("non-Windows desktop launch accepted")
	}
}

func TestRejectUnsafeInputs(t *testing.T) {
	cases := [][]string{
		{}, {"evil", "--host", "host", "--user", "dev"},
		{"terminal", "--host", "-oProxyCommand=sh", "--user", "dev"},
		{"terminal", "--host", "host; touch /tmp/pwn", "--user", "dev"},
		{"terminal", "--host", "host/path", "--user", "dev"},
		{"terminal", "--host", "u@host", "--user", "dev"},
		{"terminal", "--host", "good.host", "--user", "-oProxyCommand=evil"},
		{"terminal", "--host", "good.host", "--user", "dev", "--port", "65536"},
		{"terminal", "--host", "good.host", "--user", "dev", "--port", "-1"},
		{"terminal", "--host", "good.host", "--user", "dev", "id"},
		{"terminal", "--host", "good.host", "--user", "dev", "--identity", "/missing/key"},
		{"desktop", "--host", "good.host", "--user", "dev"},
		{"desktop", "--host", "good.host", "--port", "1", "--known-hosts", "x"},
	}
	for _, input := range cases {
		if inv, err := buildForOS("windows", input); err == nil {
			t.Fatalf("accepted invalid input %v: %+v", input, inv)
		}
	}
}

func TestValidHostAndUser(t *testing.T) {
	for _, host := range []string{"localhost", "dev-host", "dev.example.com", "127.0.0.1", "2001:db8::1"} {
		if !validHost(host) {
			t.Fatalf("valid host %q rejected", host)
		}
	}
	for _, host := range []string{"", "-dev", "dev-", "bad..host", "bad_host", "a:b", "a b", "dev\n"} {
		if validHost(host) {
			t.Fatalf("unsafe host %q accepted", host)
		}
	}
	for _, user := range []string{"jack", "_svc", "dev.user", "dev-1"} {
		if !validUser(user) {
			t.Fatalf("valid user %q rejected", user)
		}
	}
	for _, user := range []string{"", "-evil", "u@host", "x y", "x\n"} {
		if validUser(user) {
			t.Fatalf("unsafe user %q accepted", user)
		}
	}
}
