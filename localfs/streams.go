package localfs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tobychui/smbsrv"
)

/*
	streams.go

	Named streams kept as files in the internal folder beside the file they
	belong to (".smbsrv" unless Config.InternalFolder says otherwise):

		docs/report.docx:Zone.Identifier -> docs/.smbsrv/streams/report.docx/Zone.Identifier
		docs:AFP_AfpInfo                 -> .smbsrv/streams/docs/AFP_AfpInfo
		(the share root):AFP_AfpInfo     -> .smbsrv/root/AFP_AfpInfo

	so they work on every file system and need no extended attributes. Stream
	names are escaped for the disk, as they may hold characters a file name
	cannot. A file renamed or deleted over SMB takes its streams along;
	changes made on the host leave them behind.

	The root has a folder of its own beside "streams", not a name inside it:
	every name in "streams" may be a real file's, so any name chosen for the
	root there would be shared with a file of that name.
*/

const (
	streamsName = "streams"
	rootName    = "root"
)

// streamDir is the share path where the streams of a file or folder are kept.
func (f *Folder) streamDir(base string) string {
	if base == "" {
		return joinShare(f.cfg.InternalFolder, rootName)
	}
	dir, name := path.Split(base)
	return joinShare(dir, f.cfg.InternalFolder, streamsName, name)
}

// encodeStream keeps letters, digits and . _ - as they are and escapes the
// rest as %XX, so any stream name becomes one safe file name.
func encodeStream(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		safe := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
		if safe && !(c == '.' && (i == 0 || i == len(name)-1)) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func decodeStream(enc string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(enc); i++ {
		if enc[i] != '%' {
			b.WriteByte(enc[i])
			continue
		}
		if i+2 >= len(enc) {
			return "", false
		}
		var c byte
		if _, err := fmt.Sscanf(enc[i+1:i+3], "%02X", &c); err != nil {
			return "", false
		}
		b.WriteByte(c)
		i += 2
	}
	return b.String(), true
}

// Streams implements smbsrv.StreamShare: the named streams of a file or
// folder, by name.
func (s streamFolder) Streams(p string) []smbsrv.FileInfo {
	if s.checkPath(p) != nil {
		return nil
	}
	full, err := s.disk(s.streamDir(p))
	if err != nil {
		return nil
	}
	entries, err := s.readDisk(full)
	if err != nil {
		return nil
	}
	out := []smbsrv.FileInfo{}
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		name, ok := decodeStream(e.Name)
		if !ok || name == "" {
			continue
		}
		e.Name = name
		e.ID = 0
		out = append(out, e)
	}
	return out
}

// dropStreams deletes what a deleted file or folder kept beside it.
func (f *Folder) dropStreams(p string) {
	if f.cfg.NoStreams {
		return
	}
	full, err := f.disk(f.streamDir(p))
	if err != nil {
		return
	}
	os.RemoveAll(full)
}

// moveStreams takes a renamed file's streams to its new name. Whatever was
// kept for the new name goes first, even when the file brings none: they
// belong to the file the rename replaced, or to one deleted on the host.
func (f *Folder) moveStreams(oldPath, newPath string) {
	if f.cfg.NoStreams {
		return
	}
	from, err := f.disk(f.streamDir(oldPath))
	if err != nil {
		return
	}
	to, err := f.disk(f.streamDir(newPath))
	if err != nil {
		return
	}
	os.RemoveAll(to)
	if _, err := os.Lstat(from); err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(to), 0777); err != nil {
		return
	}
	//On failure the streams stay behind; the file itself moved
	os.Rename(from, to)
}
