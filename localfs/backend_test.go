package localfs

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/tobychui/smbsrv"
)

func TestNewBackendNeedsLookupAndShares(t *testing.T) {
	if _, err := NewBackend(Options{}); err == nil {
		t.Error("an empty Options must be refused")
	}
	if _, err := NewBackend(Options{Lookup: func(string) (string, []byte, bool) { return "", nil, false }}); err == nil {
		t.Error("Options without Shares must be refused")
	}
}

func TestAllow(t *testing.T) {
	none := func(string) []smbsrv.Share { return nil }
	lookup := func(string) (string, []byte, bool) { return "", nil, false }
	private, _ := NewBackend(Options{Lookup: lookup, Shares: none})
	public, _ := NewBackend(Options{Lookup: lookup, Shares: none, AllowPublicAddresses: true})
	filtered, _ := NewBackend(Options{Lookup: lookup, Shares: none, AllowIP: func(ip net.IP) bool { return !ip.Equal(net.ParseIP("192.168.1.9")) }})
	cases := []struct {
		label   string
		b       *Backend
		ip      string
		allowed bool
	}{
		{"loopback", private, "127.0.0.1", true},
		{"private v4", private, "192.168.1.20", true},
		{"private v6", private, "fd00::1", true},
		{"link-local", private, "fe80::1", true},
		{"public", private, "8.8.8.8", false},
		{"public allowed", public, "8.8.8.8", true},
		{"filtered out", filtered, "192.168.1.9", false},
		{"filter passes", filtered, "192.168.1.10", true},
		{"no address", private, "", false},
	}
	for _, tc := range cases {
		if got := tc.b.Allow(net.ParseIP(tc.ip)); got != tc.allowed {
			t.Errorf("%s: Allow(%s) = %v", tc.label, tc.ip, got)
		}
	}
}

func TestLookupHashRefusesBadHashes(t *testing.T) {
	b, _ := NewBackend(Options{
		Lookup: func(name string) (string, []byte, bool) { return name, []byte{1, 2, 3}, true },
		Shares: func(string) []smbsrv.Share { return nil },
	})
	if _, _, ok := b.LookupHash("alice"); ok {
		t.Error("a hash that is not 16 bytes must not log anyone in")
	}
}

func TestAuthLog(t *testing.T) {
	var seen []string
	b, _ := NewBackend(Options{
		Lookup:       func(string) (string, []byte, bool) { return "", nil, false },
		Shares:       func(string) []smbsrv.Share { return nil },
		OnAuth:       func(u, r string, ok bool) { seen = append(seen, u) },
		FailureDelay: time.Second,
	})
	if d := b.AuthLog("bob", "1.2.3.4:5", false); d != time.Second {
		t.Errorf("a failed login waits FailureDelay, got %v", d)
	}
	if d := b.AuthLog("bob", "1.2.3.4:5", true); d != 0 {
		t.Errorf("a good login does not wait, got %v", d)
	}
	if len(seen) != 2 {
		t.Errorf("OnAuth must see every attempt: %v", seen)
	}
}

// TestServeWithGoSMB2 runs the whole stack: the server, this backend and a
// client written by someone else.
func TestServeWithGoSMB2(t *testing.T) {
	dir := t.TempDir()
	share, err := New(Config{Name: "public", Path: dir, Comment: "Test files"})
	if err != nil {
		t.Fatal(err)
	}
	ro, err := New(Config{Name: "archive", Path: t.TempDir(), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	hash := smbsrv.NTHash("correct horse")
	backend, err := NewBackend(Options{
		Lookup: func(name string) (string, []byte, bool) {
			if strings.EqualFold(name, "alice") {
				return "alice", hash, true
			}
			return "", nil, false
		},
		Shares: func(string) []smbsrv.Share { return []smbsrv.Share{share, ro} },
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := smbsrv.New(smbsrv.Config{Address: "127.0.0.1:0", Backend: backend, LoginDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	dial := func(user, password string) (*smb2.Session, error) {
		nc, err := net.Dial("tcp", server.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: password}}
		s, err := d.Dial(nc)
		if err != nil {
			nc.Close()
			return nil, err
		}
		t.Cleanup(func() { s.Logoff() })
		return s, nil
	}

	if _, err := dial("alice", "wrong"); err == nil {
		t.Fatal("a wrong password must not log in")
	}
	session, err := dial("ALICE", "correct horse")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	names, err := session.ListSharenames()
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "public") || !strings.Contains(joined, "archive") {
		t.Errorf("share list %v", names)
	}

	fs, err := session.Mount("public")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer fs.Umount()
	if err := fs.Mkdir("docs", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := bytes.Repeat([]byte("smbsrv "), 200000) //Over one read
	if err := fs.WriteFile("docs/big.txt", content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := fs.ReadFile("docs/big.txt")
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read back %d bytes, %v", len(got), err)
	}
	if onDisk, err := os.ReadFile(dir + "/docs/big.txt"); err != nil || !bytes.Equal(onDisk, content) {
		t.Errorf("the file on disk differs: %v", err)
	}
	if err := fs.Rename("docs/big.txt", "docs/moved.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	entries, err := fs.ReadDir("docs")
	if err != nil || len(entries) != 1 || entries[0].Name() != "moved.txt" {
		t.Fatalf("listing after rename: %v %v", entries, err)
	}
	if err := fs.Remove("docs/moved.txt"); err != nil {
		t.Errorf("remove: %v", err)
	}

	//A stream is written beside the file, and its folder is never listed
	if err := fs.WriteFile("a.txt", []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("a.txt:Zone.Identifier", []byte("[ZoneTransfer]"), 0644); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	if b, err := fs.ReadFile("a.txt:Zone.Identifier"); err != nil || string(b) != "[ZoneTransfer]" {
		t.Errorf("stream read: %q %v", b, err)
	}
	root, _ := fs.ReadDir(".")
	for _, e := range root {
		if strings.EqualFold(e.Name(), DefaultInternalFolder) {
			t.Error("the stream folder must not be listed")
		}
	}
	if _, err := fs.ReadDir(DefaultInternalFolder); err == nil {
		t.Error("the stream folder must not be opened by name")
	}

	archive, err := session.Mount("archive")
	if err != nil {
		t.Fatalf("mount archive: %v", err)
	}
	defer archive.Umount()
	if err := archive.WriteFile("x.txt", []byte("x"), 0644); err == nil {
		t.Error("a read only share must refuse writes")
	}
}
