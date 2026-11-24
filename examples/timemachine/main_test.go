package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// serve runs the example in the background and returns its address.
func serve(t *testing.T, args ...string) (net.Addr, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := &bytes.Buffer{}
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, args, out, func(a net.Addr) { ready <- a }) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case a := <-ready:
		return a, out
	case err := <-done:
		t.Fatalf("run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not start")
	}
	return nil, nil
}

// TestBacksUpIntoTheFolder backs up the way a Mac does: into the TimeMachine
// share, which reports the size limit and keeps the files in the folder.
func TestBacksUpIntoTheFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backup")
	addr, out := serve(t, "-addr", "127.0.0.1:0", "-dir", dir, "-user", "alice", "-pw", "secret", "-max", "1")

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("the folder was not created: %v", err)
	}
	if !strings.Contains(out.String(), "/"+shareName) || !strings.Contains(out.String(), "up to 1 GB") {
		t.Errorf("instructions: %s", out.String())
	}

	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "ALICE", Password: "secret"}}
	s, err := d.Dial(nc)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer s.Logoff()
	share, err := s.Mount(shareName)
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer share.Umount()

	if err := share.MkdirAll("Mac.sparsebundle/bands", 0755); err != nil {
		t.Fatal(err)
	}
	if err := share.WriteFile("Mac.sparsebundle/bands/0", []byte("band"), 0644); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "Mac.sparsebundle", "bands", "0")); err != nil || string(b) != "band" {
		t.Errorf("the backup is not in the folder: %q %v", b, err)
	}
	fs, err := share.Statfs("Mac.sparsebundle")
	if err != nil {
		t.Fatal(err)
	}
	//go-smb2 calls a sector a block, and sectors per unit the fragment size
	if total := fs.TotalBlockCount() * fs.FragmentSize() * fs.BlockSize(); total != 1<<30 {
		t.Errorf("size %d, want the 1 GB limit", total)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	addr, _ := serve(t, "-addr", "127.0.0.1:0", "-dir", t.TempDir(), "-user", "alice", "-pw", "secret")
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "wrong"}}
	if _, err := d.Dial(nc); err == nil {
		t.Error("a wrong password logged in")
	}
}

func TestPasswordFromEnvironment(t *testing.T) {
	t.Setenv("SMBSRV_PASSWORD", "from-env")
	addr, _ := serve(t, "-addr", "127.0.0.1:0", "-dir", t.TempDir(), "-user", "bob")
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "bob", Password: "from-env"}}
	s, err := d.Dial(nc)
	if err != nil {
		t.Fatalf("login with the variable's password: %v", err)
	}
	s.Logoff()
}

func TestRefusesBadArguments(t *testing.T) {
	t.Setenv("SMBSRV_PASSWORD", "")
	tests := []struct {
		name string
		args []string
	}{
		{"no user", []string{"-pw", "secret"}},
		{"no password", []string{"-user", "alice"}},
		{"limit too large", []string{"-user", "alice", "-pw", "secret", "-max", "99999999999"}},
		{"unknown flag", []string{"-nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"-addr", "127.0.0.1:0", "-dir", t.TempDir()}, tt.args...)
			if err := run(context.Background(), args, &bytes.Buffer{}, nil); err == nil {
				t.Error("accepted")
			}
		})
	}
}
