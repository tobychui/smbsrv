package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNetbiosName(t *testing.T) {
	cases := []struct{ host, want string }{
		{"nas", "NAS"},
		{"my-server.local", "MY-SERVER"},
		{"a_b c", "A-B-C"},
		{"averyveryverylonghostname", "AVERYVERYVERYLO"},
		{"", "SMBSRV"},
		{"---", "SMBSRV"},
		{"café", "CAF"},
	}
	for _, tc := range cases {
		if got := netbiosName(tc.host); got != tc.want {
			t.Errorf("netbiosName(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestValidUsername(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"alice", true},
		{"Bob.Smith", true},
		{"user@example.com", true},
		{"王小明", true},
		{"", false},
		{" alice", false},
		{"alice ", false},
		{`dom\alice`, false},
		{"a/b", false},
		{"a:b", false},
		{"tab\tname", false},
		{strings.Repeat("x", 65), false},
	}
	for _, tc := range cases {
		if err := ValidUsername(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidUsername(%q) = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestSetUser(t *testing.T) {
	cfg := NewConfig()
	created, err := cfg.SetUser("alice", "password")
	if err != nil || !created {
		t.Fatalf("first SetUser: %v %v", created, err)
	}
	//The well known NT hash of "password"
	if got := cfg.Users[0].NTHash; got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Errorf("hash %s", got)
	}
	created, err = cfg.SetUser("ALICE", "another")
	if err != nil || created {
		t.Fatalf("SetUser of an existing name must update it: %v %v", created, err)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Name != "alice" || cfg.Users[0].NTHash == "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Errorf("update went wrong: %+v", cfg.Users)
	}
	if _, err := cfg.SetUser("bob", ""); err == nil {
		t.Error("an empty password must be refused")
	}
	if _, err := cfg.SetUser("a:b", "pw"); err == nil {
		t.Error("a bad name must be refused")
	}
}

func TestDeleteUser(t *testing.T) {
	cfg := NewConfig()
	cfg.SetUser("alice", "pw")
	cfg.SetUser("bob", "pw")
	cfg.Shares = []ShareConfig{{Name: "s", Path: t.TempDir(), Users: []string{"bob"}}}
	if err := cfg.DeleteUser("BOB"); err != nil {
		t.Fatal(err)
	}
	if cfg.FindUser("bob") != nil || cfg.FindUser("alice") == nil {
		t.Errorf("users left: %+v", cfg.Users)
	}
	//An empty list would open the share to everyone
	if len(cfg.Shares[0].Users) != 1 {
		t.Error("share lists must keep the deleted name")
	}
	if err := cfg.DeleteUser("carol"); err == nil {
		t.Error("deleting a missing user must fail")
	}
}

func TestAddShare(t *testing.T) {
	parent := t.TempDir()
	photos := filepath.Join(parent, "Photos")
	os.Mkdir(photos, 0755)
	file := filepath.Join(parent, "file.txt")
	os.WriteFile(file, []byte("x"), 0644)

	cfg := NewConfig()
	stored, updated, err := cfg.AddShare(ShareConfig{Path: photos})
	if err != nil || updated || stored.Name != "Photos" || stored.Path != photos {
		t.Fatalf("default name: %+v %v %v", stored, updated, err)
	}
	stored, updated, err = cfg.AddShare(ShareConfig{Name: "photos", Path: photos, ReadOnly: true, Users: []string{" alice ", "", "bob"}})
	if err != nil || !updated {
		t.Fatalf("a share of the same name must be updated: %v %v", updated, err)
	}
	if len(cfg.Shares) != 1 || !cfg.Shares[0].ReadOnly || strings.Join(cfg.Shares[0].Users, ",") != "alice,bob" {
		t.Errorf("after update: %+v", cfg.Shares)
	}
	if _, _, err := cfg.AddShare(ShareConfig{Name: "other", Path: photos}); err != nil {
		t.Errorf("one folder may be shared under two names: %v", err)
	}

	bad := []struct {
		label string
		s     ShareConfig
	}{
		{"no path", ShareConfig{Name: "x"}},
		{"missing", ShareConfig{Path: filepath.Join(parent, "missing")}},
		{"a file", ShareConfig{Path: file}},
		{"bad name", ShareConfig{Name: "a:b", Path: photos}},
		{"reserved name", ShareConfig{Name: "IPC$", Path: photos}},
	}
	for _, tc := range bad {
		if _, _, err := cfg.AddShare(tc.s); err == nil {
			t.Errorf("%s: AddShare must fail", tc.label)
		}
	}
}

func TestRemoveShare(t *testing.T) {
	cfg := NewConfig()
	cfg.AddShare(ShareConfig{Name: "a", Path: t.TempDir()})
	if err := cfg.RemoveShare("A"); err != nil || len(cfg.Shares) != 0 {
		t.Errorf("remove: %v %+v", err, cfg.Shares)
	}
	if err := cfg.RemoveShare("a"); err == nil {
		t.Error("removing a missing share must fail")
	}
}

func TestShareAllows(t *testing.T) {
	cases := []struct {
		users []string
		user  string
		want  bool
	}{
		{nil, "anyone", true},
		{[]string{"alice"}, "ALICE", true},
		{[]string{"alice", "bob"}, "bob", true},
		{[]string{"alice"}, "bob", false},
	}
	for _, tc := range cases {
		if got := (ShareConfig{Users: tc.users}).Allows(tc.user); got != tc.want {
			t.Errorf("%v allows %q = %v", tc.users, tc.user, got)
		}
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("a missing file gives the defaults: %v", err)
	}
	if cfg.Address != ":445" || len(cfg.GUID) != 32 {
		t.Errorf("defaults: %+v", cfg)
	}
	cfg.SetUser("alice", "pw")
	cfg.AddShare(ShareConfig{Name: "data", Path: t.TempDir()})
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file must be gone")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
			t.Errorf("the file holds password hashes and must be private, got %v", fi.Mode().Perm())
		}
	}
	back, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.GUID != cfg.GUID || len(back.Users) != 1 || back.Users[0].NTHash != cfg.Users[0].NTHash || len(back.Shares) != 1 {
		t.Errorf("round trip: %+v", back)
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	good := `"guid": "00112233445566778899aabbccddeeff", "address": ":445"`
	cases := []struct{ label, body string }{
		{"not json", `{`},
		{"bad guid", `{"guid": "xyz", "address": ":445"}`},
		{"no address", `{"guid": "00112233445566778899aabbccddeeff"}`},
		{"bad hash", `{` + good + `, "users": [{"name": "a", "ntHash": "1234"}]}`},
		{"twice", `{` + good + `, "users": [{"name": "a", "ntHash": "8846f7eaee8fb117ad06bdd830b7586c"}, {"name": "A", "ntHash": "8846f7eaee8fb117ad06bdd830b7586c"}]}`},
		{"share twice", `{` + good + `, "shares": [{"name": "s", "path": "/x"}, {"name": "S", "path": "/y"}]}`},
		{"share without path", `{` + good + `, "shares": [{"name": "s"}]}`},
	}
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), ConfigFileName)
		os.WriteFile(path, []byte(tc.body), 0600)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s: LoadConfig must fail", tc.label)
		}
	}
}
