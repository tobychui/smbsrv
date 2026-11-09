package localfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tobychui/smbsrv"
)

func newTestFolder(t *testing.T, cfg Config) (smbsrv.Share, string) {
	t.Helper()
	dir := t.TempDir()
	if cfg.Name == "" {
		cfg.Name = "data"
	}
	cfg.Path = dir
	share, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	root, _ := filepath.EvalSymlinks(dir)
	return share, root
}

func writeShareFile(t *testing.T, s smbsrv.Share, p, content string) {
	t.Helper()
	f, err := s.Open(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatalf("open %q: %v", p, err)
	}
	if _, err := f.WriteAt([]byte(content), 0); err != nil {
		t.Fatalf("write %q: %v", p, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %q: %v", p, err)
	}
}

func readShareFile(t *testing.T, s smbsrv.Share, p string) string {
	t.Helper()
	f, err := s.Open(p, os.O_RDONLY)
	if err != nil {
		t.Fatalf("open %q: %v", p, err)
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read %q: %v", p, err)
	}
	return string(buf[:n])
}

func TestValidShareName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"public", true},
		{"My Photos", true},
		{"data$", true},
		{"", false},
		{"IPC$", false},
		{"ipc$", false},
		{"a/b", false},
		{`a\b`, false},
		{"a:b", false},
		{"what?", false},
		{"tab\there", false},
		{string(make([]rune, 81)), false},
	}
	for _, tc := range cases {
		if err := ValidShareName(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidShareName(%q) = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestNewRefusesBadFolders(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	os.WriteFile(file, []byte("x"), 0644)
	cases := []struct {
		label string
		cfg   Config
	}{
		{"no path", Config{Name: "a"}},
		{"missing folder", Config{Name: "a", Path: filepath.Join(dir, "missing")}},
		{"a file", Config{Name: "a", Path: file}},
		{"bad name", Config{Name: "a:b", Path: dir}},
		{"internal folder with a slash", Config{Name: "a", Path: dir, InternalFolder: "x/y"}},
	}
	for _, tc := range cases {
		if _, err := New(tc.cfg); err == nil {
			t.Errorf("%s: New must fail", tc.label)
		}
	}
}

func TestReadWriteListRename(t *testing.T) {
	s, root := newTestFolder(t, Config{})
	if err := s.Mkdir("docs"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeShareFile(t, s, "docs/a.txt", "hello")
	if got := readShareFile(t, s, "docs/a.txt"); got != "hello" {
		t.Errorf("read back %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "a.txt")); err != nil {
		t.Errorf("the file must be on disk: %v", err)
	}

	list, err := s.ReadDir("docs")
	if err != nil || len(list) != 1 || list[0].Name != "a.txt" || list[0].Size != 5 || list[0].IsDir {
		t.Fatalf("listing: %+v %v", list, err)
	}
	info, err := s.Stat("docs/a.txt")
	if err != nil || info.Name != "a.txt" || info.Size != 5 {
		t.Errorf("stat: %+v %v", info, err)
	}

	if err := s.Rename("docs/a.txt", "docs/b.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := s.Stat("docs/a.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old name must be gone: %v", err)
	}
	if err := s.Remove("docs/b.txt"); err != nil {
		t.Errorf("remove: %v", err)
	}
	if err := s.Remove("docs"); err != nil {
		t.Errorf("remove folder: %v", err)
	}
	if total, free := s.Usage(); total == 0 || free > total {
		t.Errorf("usage %d free of %d", free, total)
	}
}

func TestRenameWhileOpen(t *testing.T) {
	//Clients rename files that they, or another client, still hold open
	s, _ := newTestFolder(t, Config{})
	writeShareFile(t, s, "a.txt", "content")
	f, err := s.Open("a.txt", os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := s.Rename("a.txt", "b.txt"); err != nil {
		t.Fatalf("rename of an open file: %v", err)
	}
	buf := make([]byte, 7)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "content" {
		t.Errorf("the open handle must still read the file: %q %v", buf, err)
	}
}

func TestPathsStayInside(t *testing.T) {
	s, root := newTestFolder(t, Config{})
	os.MkdirAll(filepath.Join(root, ".smbsrv", "streams"), 0755)
	cases := []string{
		"..",
		"a/../..",
		".smbsrv",
		".smbsrv/streams",
		".SMBSRV",
		"docs/.smbsrv/x",
		"",
	}
	for _, p := range cases {
		_, err := s.Stat(p)
		if p == "" {
			if err != nil {
				t.Errorf("the root must be reachable: %v", err)
			}
			continue
		}
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("Stat(%q) must be refused, got %v", p, err)
		}
	}
}

func TestLinksLeadingOffAreRefused(t *testing.T) {
	s, root := newTestFolder(t, Config{})
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644)
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Skipf("cannot create links here: %v", err)
	}
	os.Mkdir(filepath.Join(root, "in"), 0755)
	os.WriteFile(filepath.Join(root, "in", "ok.txt"), []byte("ok"), 0644)
	if err := os.Symlink(filepath.Join(root, "in"), filepath.Join(root, "inlink")); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Stat("out/secret.txt"); err == nil {
		t.Error("a file behind a link off the folder must be refused")
	}
	if _, err := s.Open("out/new.txt", os.O_RDWR|os.O_CREATE); err == nil {
		t.Error("creating through a link off the folder must be refused")
	}
	if got := readShareFile(t, s, "inlink/ok.txt"); got != "ok" {
		t.Errorf("a link inside the folder must work, read %q", got)
	}
	list, _ := s.ReadDir("")
	for _, e := range list {
		if e.Name == "out" {
			t.Error("a link off the folder must not be listed")
		}
		if e.Name == "inlink" && !e.IsDir {
			t.Error("a link to a folder must be listed as a folder")
		}
	}
}

func TestStreams(t *testing.T) {
	s, root := newTestFolder(t, Config{})
	ss, ok := s.(smbsrv.StreamShare)
	if !ok {
		t.Fatal("a folder keeps streams unless NoStreams is set")
	}
	if is, ok := s.(smbsrv.InternalShare); !ok || is.InternalFolder() != ".smbsrv" {
		t.Fatal("the stream folder must be reported to the server")
	}
	os.Mkdir(filepath.Join(root, "docs"), 0755)
	writeShareFile(t, s, "docs/a.txt", "data")
	stream := "docs/a.txt" + smbsrv.StreamSeparator + "Zone.Identifier"
	writeShareFile(t, s, stream, "[ZoneTransfer]")
	rootStream := smbsrv.StreamSeparator + "AFP_AfpInfo"
	writeShareFile(t, s, rootStream, "root info")

	if got := readShareFile(t, s, stream); got != "[ZoneTransfer]" {
		t.Errorf("stream read back %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", ".smbsrv", "streams", "a.txt", "Zone.Identifier")); err != nil {
		t.Errorf("the stream must be kept beside the file: %v", err)
	}
	if got := ss.Streams("docs/a.txt"); len(got) != 1 || got[0].Name != "Zone.Identifier" || got[0].Size != 14 {
		t.Errorf("streams of the file: %+v", got)
	}
	if got := ss.Streams(""); len(got) != 1 || got[0].Name != "AFP_AfpInfo" {
		t.Errorf("streams of the root: %+v", got)
	}

	//A rename takes the streams along, a delete drops them
	if err := s.Rename("docs/a.txt", "docs/b.txt"); err != nil {
		t.Fatal(err)
	}
	if got := ss.Streams("docs/a.txt"); len(got) != 0 {
		t.Errorf("the old name must have no streams left: %+v", got)
	}
	if got := ss.Streams("docs/b.txt"); len(got) != 1 {
		t.Errorf("the streams must follow the rename: %+v", got)
	}
	if err := s.Remove("docs/b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", ".smbsrv", "streams", "b.txt")); !os.IsNotExist(err) {
		t.Errorf("the streams of a deleted file must go: %v", err)
	}
	//A folder holding only the stream folder can be removed
	if err := s.Remove("docs"); err != nil {
		t.Errorf("remove of a folder with only streams left: %v", err)
	}
}

func TestNoStreams(t *testing.T) {
	s, _ := newTestFolder(t, Config{NoStreams: true})
	if _, ok := s.(smbsrv.StreamShare); ok {
		t.Error("NoStreams must not offer streams")
	}
	if is, ok := s.(smbsrv.InternalShare); ok && is.InternalFolder() != "" {
		t.Error("NoStreams has no internal folder to hide")
	}
	if _, err := s.Open("a.txt"+smbsrv.StreamSeparator+"x", os.O_RDWR|os.O_CREATE); err == nil {
		t.Error("a stream open must be refused")
	}
	//The name is an ordinary one again
	if err := s.Mkdir(".smbsrv"); err != nil {
		t.Errorf("mkdir .smbsrv: %v", err)
	}
}

func TestReadOnly(t *testing.T) {
	s, _ := newTestFolder(t, Config{ReadOnly: true})
	if !s.ReadOnly() || s.CanWrite("a.txt") || !s.CanRead("a.txt") {
		t.Error("a read only folder must be readable and not writable")
	}
}

func TestEncodeStream(t *testing.T) {
	cases := []struct{ in, out string }{
		{"Zone.Identifier", "Zone.Identifier"},
		{"AFP_AfpInfo", "AFP_AfpInfo"},
		{"com.apple.metadata:_kMDItemUserTags", "com.apple.metadata%3A_kMDItemUserTags"},
		{".hidden", "%2Ehidden"},
		{"trailing.", "trailing%2E"},
		{"a b/c", "a%20b%2Fc"},
	}
	for _, tc := range cases {
		got := encodeStream(tc.in)
		if got != tc.out {
			t.Errorf("encodeStream(%q) = %q, want %q", tc.in, got, tc.out)
		}
		if back, ok := decodeStream(got); !ok || back != tc.in {
			t.Errorf("decodeStream(%q) = %q %v", got, back, ok)
		}
	}
	if _, ok := decodeStream("bad%4"); ok {
		t.Error("a cut escape must not decode")
	}
}

func TestBadNamesOnThisSystem(t *testing.T) {
	s, _ := newTestFolder(t, Config{})
	names := []string{"a:b.txt", "CON", "nul.txt", "trailing.", "trailing "}
	for _, name := range names {
		_, err := s.Open(name, os.O_RDWR|os.O_CREATE)
		if runtime.GOOS == "windows" {
			if !errors.Is(err, os.ErrPermission) {
				t.Errorf("%q must be refused on Windows, got %v", name, err)
			}
		} else if err != nil {
			t.Errorf("%q is a valid name here: %v", name, err)
		}
	}
}
