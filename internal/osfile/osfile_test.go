package osfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenFlags(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.txt")
	os.WriteFile(existing, []byte("old content"), 0644)
	cases := []struct {
		label    string
		name     string
		flag     int
		wantErr  error
		wantSize int64
	}{
		{"open existing", existing, os.O_RDONLY, nil, 11},
		{"missing", filepath.Join(dir, "missing.txt"), os.O_RDONLY, os.ErrNotExist, 0},
		{"create new", filepath.Join(dir, "new.txt"), os.O_RDWR | os.O_CREATE, nil, 0},
		{"exclusive on existing", existing, os.O_RDWR | os.O_CREATE | os.O_EXCL, os.ErrExist, 0},
		{"truncate", existing, os.O_RDWR | os.O_TRUNC, nil, 0},
	}
	for _, tc := range cases {
		f, err := Open(tc.name, tc.flag, 0644)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s: got %v, want %v", tc.label, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.label, err)
			continue
		}
		if fi, _ := f.Stat(); fi.Size() != tc.wantSize {
			t.Errorf("%s: size %d, want %d", tc.label, fi.Size(), tc.wantSize)
		}
		f.Close()
	}
}

func TestRenameAndRemoveWhileOpen(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	f, err := Open(a, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(dir, "b.txt")
	if err := os.Rename(a, b); err != nil {
		t.Fatalf("rename of an open file: %v", err)
	}
	if err := os.Remove(b); err != nil {
		t.Fatalf("remove of an open file: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "data" {
		t.Errorf("the handle must keep working: %q %v", buf, err)
	}
}

func TestLongPath(t *testing.T) {
	dir := t.TempDir()
	deep := dir
	for len(deep) < 300 {
		deep = filepath.Join(deep, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Skipf("this file system cannot hold the path: %v", err)
	}
	f, err := Open(filepath.Join(deep, "file.txt"), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("a path over 260 characters: %v", err)
	}
	f.Close()
}
