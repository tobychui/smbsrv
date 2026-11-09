package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// runCLI runs the command with these arguments and returns its exit code and
// output.
func runCLI(t *testing.T, stdin *os.File, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, stdin, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunManagesUsersAndShares(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	folder := t.TempDir()

	//The two examples of the README
	if code, out, errOut := runCLI(t, nil, "-c", path, "-a", "user", "-pw", "very_secure_password"); code != 0 || !strings.Contains(out, "Added user user") {
		t.Fatalf("-a: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runCLI(t, nil, "-c", path, "-f", folder); code != 0 || !strings.Contains(out, "Shared") {
		t.Fatalf("-f: %d %q %q", code, out, errOut)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Name != "user" || len(cfg.Users[0].NTHash) != 32 {
		t.Errorf("users: %+v", cfg.Users)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0].Path != folder {
		t.Errorf("shares: %+v", cfg.Shares)
	}
	if strings.Contains(mustRead(t, path), "very_secure_password") {
		t.Error("the password itself must never be stored")
	}

	//Change a share, list, remove
	name := filepath.Base(folder)
	if code, out, _ := runCLI(t, nil, "-c", path, "-f", folder, "-ro", "-u", "user"); code != 0 || !strings.Contains(out, "Updated share") {
		t.Errorf("update share: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, nil, "-c", path, "-l"); code != 0 || !strings.Contains(out, "read only, user") {
		t.Errorf("list: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, nil, "-c", path, "-rm", name); code != 0 {
		t.Errorf("-rm: %d", code)
	}
	if code, _, _ := runCLI(t, nil, "-c", path, "-d", "user"); code != 0 {
		t.Errorf("-d: %d", code)
	}
	cfg, _ = LoadConfig(path)
	if len(cfg.Users) != 0 || len(cfg.Shares) != 0 {
		t.Errorf("after removing: %+v %+v", cfg.Users, cfg.Shares)
	}
}

func TestRunRefusesMisuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	cases := []struct {
		label string
		args  []string
		code  int
	}{
		{"-pw alone", []string{"-pw", "x"}, 2},
		{"-ro alone", []string{"-ro"}, 2},
		{"-n alone", []string{"-n", "x"}, 2},
		{"stray argument", []string{"-a", "bob", "-pw", "x", "extra"}, 2},
		{"unknown flag", []string{"-zzz"}, 2},
		{"bad user name", []string{"-a", "a:b", "-pw", "x"}, 1},
		{"missing folder", []string{"-f", filepath.Join(t.TempDir(), "missing")}, 1},
		{"remove missing share", []string{"-rm", "nothing"}, 1},
		{"nothing to serve", []string{}, 1},
	}
	for _, tc := range cases {
		args := append([]string{"-c", path}, tc.args...)
		if code, _, _ := runCLI(t, nil, args...); code != tc.code {
			t.Errorf("%s: exit %d, want %d", tc.label, code, tc.code)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("failed commands must not create the file")
	}
}

func TestPasswordFromStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	in := filepath.Join(t.TempDir(), "stdin")
	os.WriteFile(in, []byte("piped secret\r\n"), 0600)
	stdin, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if code, _, errOut := runCLI(t, stdin, "-c", path, "-a", "carol"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	cfg, _ := LoadConfig(path)
	check := NewConfig()
	check.SetUser("carol", "piped secret")
	if cfg.FindUser("carol") == nil || cfg.FindUser("carol").NTHash != check.Users[0].NTHash {
		t.Error("the password must be read from stdin, without its line end")
	}
}

func TestBindHint(t *testing.T) {
	cases := []struct {
		label   string
		addr    string
		err     error
		contain string
	}{
		{"permission", ":139", os.ErrPermission, "setcap"},
		{"in use", ":1445", errors.New("listen tcp :1445: bind: address already in use"), "Samba"},
		{"other", ":1445", errors.New("something else"), ""},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases, struct {
			label   string
			addr    string
			err     error
			contain string
		}{"windows 445", ":445", errors.New("bind: An attempt was made to access a socket"), "TCPPORT"})
	}
	for _, tc := range cases {
		got := bindHint(tc.addr, tc.err)
		if (tc.contain == "" && got != "") || !strings.Contains(got, tc.contain) {
			t.Errorf("%s: %q", tc.label, got)
		}
	}
}

// TestServeEndToEnd starts the server from a file the CLI wrote, uses it with
// go-smb2, and changes a password while it runs.
func TestServeEndToEnd(t *testing.T) {
	old := reloadInterval
	reloadInterval = 0
	t.Cleanup(func() { reloadInterval = old })

	path := filepath.Join(t.TempDir(), ConfigFileName)
	folder := t.TempDir()
	runCLI(t, nil, "-c", path, "-a", "alice", "-pw", "first password")
	runCLI(t, nil, "-c", path, "-a", "bob", "-pw", "bob password")
	runCLI(t, nil, "-c", path, "-f", folder, "-n", "files")
	runCLI(t, nil, "-c", path, "-f", t.TempDir(), "-n", "private", "-u", "bob")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	var out, logs bytes.Buffer
	go func() {
		off := false
		done <- serve(ctx, path, cfg, serveOptions{address: "127.0.0.1:0", announce: &off, ready: func(a net.Addr) { ready <- a }}, &out, &logs)
	}()
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not start")
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve returned %v", err)
		}
	}()

	dial := func(user, password string) (*smb2.Session, error) {
		nc, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		s, err := (&smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: password}}).Dial(nc)
		if err != nil {
			nc.Close()
			return nil, err
		}
		return s, nil
	}

	session, err := dial("alice", "first password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer session.Logoff()
	names, _ := session.ListSharenames()
	if strings.Contains(strings.Join(names, ","), "private") {
		t.Errorf("alice must not see bob's share: %v", names)
	}
	if _, err := session.Mount("private"); err == nil {
		t.Error("alice must not open bob's share")
	}
	fs, err := session.Mount("files")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := fs.WriteFile("hello.txt", []byte("hello from smbsrv"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := mustRead(t, filepath.Join(folder, "hello.txt")); got != "hello from smbsrv" {
		t.Errorf("on disk: %q", got)
	}

	//A new password applies without a restart and logs the old session out
	if code, _, errOut := runCLI(t, nil, "-c", path, "-a", "alice", "-pw", "second password"); code != 0 {
		t.Fatalf("change password: %s", errOut)
	}
	if _, err := dial("alice", "first password"); err == nil {
		t.Error("the old password must stop working")
	}
	again, err := dial("alice", "second password")
	if err != nil {
		t.Fatalf("the new password must work: %v", err)
	}
	again.Logoff()
	if _, err := fs.ReadFile("hello.txt"); err == nil {
		t.Error("the session of the old password must be logged out")
	}
	if !strings.Contains(out.String(), `\files`) {
		t.Errorf("the start banner must list the shares: %q", out.String())
	}
}

func TestServeNeedsUsersAndShares(t *testing.T) {
	cfg := NewConfig()
	if err := serve(context.Background(), "x.json", cfg, serveOptions{}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "-a NAME") {
		t.Errorf("no users: %v", err)
	}
	cfg.SetUser("alice", "pw")
	if err := serve(context.Background(), "x.json", cfg, serveOptions{}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "-f FOLDER") {
		t.Errorf("no shares: %v", err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
