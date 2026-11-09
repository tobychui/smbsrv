// Package localfs serves folders of the local disk over smbsrv.
//
// New turns one folder into a smbsrv.Share, and NewBackend puts shares and
// accounts together into a smbsrv.Backend:
//
//	share, _ := localfs.New(localfs.Config{Name: "public", Path: "/srv/public"})
//	hash := smbsrv.NTHash("secret")
//	backend, _ := localfs.NewBackend(localfs.Options{
//		Lookup: func(name string) (string, []byte, bool) {
//			if strings.EqualFold(name, "alice") {
//				return "alice", hash, true
//			}
//			return "", nil, false
//		},
//		Shares: func(username string) []smbsrv.Share { return []smbsrv.Share{share} },
//	})
//	server, _ := smbsrv.New(smbsrv.Config{Address: ":445", Backend: backend})
//	server.Start()
package localfs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tobychui/smbsrv"
	"github.com/tobychui/smbsrv/internal/osfile"
)

// DefaultInternalFolder is where a share keeps named streams unless
// Config.InternalFolder names another folder.
const DefaultInternalFolder = ".smbsrv"

// ErrOutside is returned for a path, or a link along it, that leads off the
// shared folder.
var ErrOutside = os.ErrPermission

// ErrBadName is returned for a name the local file system cannot hold as it
// is, such as "a:b" or "CON" on Windows. The client sees it as access denied.
var ErrBadName = fmt.Errorf("localfs: the name cannot be stored here: %w", os.ErrPermission)

// Config describes one shared folder.
type Config struct {
	//Name is what clients open, as \\server\Name
	Name string

	//Path is the folder on the local disk
	Path string

	//Comment is shown beside the name in share listings
	Comment string

	//ReadOnly refuses every change
	ReadOnly bool

	//NoStreams turns named streams off. With them on, the streams clients
	//attach to files (the download marker Windows writes, Finder tags and
	//resource forks of macOS) are kept as files in a hidden folder beside
	//them. With them off, Windows drops them and macOS writes ._ files.
	NoStreams bool

	//InternalFolder names that hidden folder; empty is ".smbsrv". It is left
	//out of listings and cannot be opened over SMB.
	InternalFolder string
}

// Folder is a smbsrv.Share over a folder of the local disk. Everything it
// serves stays inside that folder: symbolic links leading off it are hidden
// from listings and refused.
type Folder struct {
	cfg  Config
	root string //Absolute, links resolved
	key  string
}

// streamFolder is a Folder that keeps named streams. It is a type of its own
// because the server asks for the Streams method to decide whether a share
// has streams at all.
type streamFolder struct{ *Folder }

// New opens a folder for sharing. The folder must exist.
func New(cfg Config) (smbsrv.Share, error) {
	f, err := newFolder(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.NoStreams {
		return f, nil
	}
	return streamFolder{f}, nil
}

func newFolder(cfg Config) (*Folder, error) {
	if err := ValidShareName(cfg.Name); err != nil {
		return nil, err
	}
	if cfg.Path == "" {
		return nil, errors.New("localfs: a folder is required")
	}
	if cfg.InternalFolder == "" {
		cfg.InternalFolder = DefaultInternalFolder
	}
	if strings.ContainsAny(cfg.InternalFolder, `/\`) || cfg.InternalFolder == "." || cfg.InternalFolder == ".." {
		return nil, errors.New("localfs: the internal folder must be a plain name")
	}
	abs, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("localfs: %s is not a folder", cfg.Path)
	}
	key := root
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		//Their disks ignore case, so two spellings are the same files
		key = strings.ToLower(key)
	}
	return &Folder{cfg: cfg, root: root, key: "localfs:" + key}, nil
}

// ValidShareName reports whether a name can be a share name: 1 to 80
// characters, none of \ / : * ? " < > | or control characters, and not IPC$.
func ValidShareName(name string) error {
	if name == "" {
		return errors.New("localfs: a share name is required")
	}
	if len([]rune(name)) > 80 {
		return errors.New("localfs: a share name has at most 80 characters")
	}
	if strings.EqualFold(name, "IPC$") {
		return errors.New("localfs: IPC$ is reserved")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`\/:*?"<>|`, r) {
			return fmt.Errorf("localfs: a share name cannot hold %q", r)
		}
	}
	return nil
}

// Root is the folder being shared, with links resolved.
func (f *Folder) Root() string { return f.root }

func (f *Folder) Name() string    { return f.cfg.Name }
func (f *Folder) Comment() string { return f.cfg.Comment }
func (f *Folder) Key() string     { return f.key }
func (f *Folder) ReadOnly() bool  { return f.cfg.ReadOnly }

// InternalFolder implements smbsrv.InternalShare, so the server hides the
// folder streams are kept in.
func (f *Folder) InternalFolder() string {
	if f.cfg.NoStreams {
		return ""
	}
	return f.cfg.InternalFolder
}

// CanRead and CanWrite allow everything: a Folder is the same for every user.
// Per user rules belong in the Backend's Shares, which can hand a user a
// read only Folder or none at all.
func (f *Folder) CanRead(p string) bool  { return true }
func (f *Folder) CanWrite(p string) bool { return !f.cfg.ReadOnly }

// CanPoll lets watched folders be listed every few seconds, so that changes
// made on the host reach clients.
func (f *Folder) CanPoll() bool { return true }

// real turns a share path from the server into a path on disk. Paths into the
// internal folder are refused: the server reaches streams with the stream
// separator, never by that folder's name.
func (f *Folder) real(p string) (string, error) {
	base, stream, isStream := strings.Cut(p, smbsrv.StreamSeparator)
	if err := f.checkPath(base); err != nil {
		return "", err
	}
	if isStream {
		if f.cfg.NoStreams || stream == "" {
			return "", ErrBadName
		}
		base = joinShare(f.streamDir(base), encodeStream(stream))
	}
	return f.disk(base)
}

// checkPath refuses names the disk would read differently from the server.
func (f *Folder) checkPath(p string) error {
	if p == "" {
		return nil
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return ErrBadName
		}
		if !f.cfg.NoStreams && sameName(trimTrailing(part), f.cfg.InternalFolder) {
			return ErrOutside
		}
		if err := checkComponent(part); err != nil {
			return err
		}
	}
	return nil
}

// sameName compares names the way the disk may: ignoring case.
func sameName(a, b string) bool { return strings.EqualFold(a, b) }

// trimTrailing drops what Windows drops from the end of a name.
func trimTrailing(name string) string { return strings.TrimRight(name, ". ") }

// disk joins a share path to the root, without the name checks, and makes
// sure no link along it leads off the folder.
func (f *Folder) disk(p string) (string, error) {
	full := filepath.Join(f.root, filepath.FromSlash(p))
	if full != f.root && !strings.HasPrefix(full, f.root+string(filepath.Separator)) {
		return "", ErrOutside
	}
	if err := f.confine(full); err != nil {
		return "", err
	}
	return full, nil
}

// confine refuses a path that a symbolic link carries off the folder. The
// deepest part that exists is checked, so a new file below a link is caught
// too, and a dangling link is refused because writing through it would create
// the target somewhere else.
func (f *Folder) confine(full string) error {
	for p := full; ; {
		resolved, err := filepath.EvalSymlinks(p)
		if err == nil {
			abs, err := filepath.Abs(resolved)
			if err != nil {
				return err
			}
			if abs != f.root && !strings.HasPrefix(abs, f.root+string(filepath.Separator)) {
				return ErrOutside
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			//Not a link problem, the operation itself will report it
			return nil
		}
		if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return ErrOutside
		}
		parent := filepath.Dir(p)
		if parent == p || len(parent) < len(f.root) {
			return nil
		}
		p = parent
	}
}

func infoOf(name string, fi os.FileInfo) smbsrv.FileInfo {
	return smbsrv.FileInfo{
		Name:      name,
		Size:      fi.Size(),
		IsDir:     fi.IsDir(),
		ModTime:   fi.ModTime(),
		BirthTime: birthTime(fi),
		ID:        fileID(fi),
	}
}

func (f *Folder) Stat(p string) (smbsrv.FileInfo, error) {
	full, err := f.real(p)
	if err != nil {
		return smbsrv.FileInfo{}, err
	}
	fi, err := os.Stat(full)
	if err != nil {
		return smbsrv.FileInfo{}, err
	}
	name := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		name = p[i+1:]
	}
	return infoOf(name, fi), nil
}

func (f *Folder) ReadDir(p string) ([]smbsrv.FileInfo, error) {
	full, err := f.real(p)
	if err != nil {
		return nil, err
	}
	return f.readDisk(full)
}

// readDisk lists a folder on disk. Links are reported as what they point at,
// and those leading off the folder are left out.
func (f *Folder) readDisk(full string) ([]smbsrv.FileInfo, error) {
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	out := make([]smbsrv.FileInfo, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue //Gone since the listing was read
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			child := filepath.Join(full, e.Name())
			if f.confine(child) != nil {
				continue
			}
			target, err := os.Stat(child)
			if err != nil {
				continue
			}
			fi = target
		}
		out = append(out, infoOf(e.Name(), fi))
	}
	return out, nil
}

func (f *Folder) Open(p string, flag int) (smbsrv.File, error) {
	full, err := f.real(p)
	if err != nil {
		return nil, err
	}
	if flag&os.O_CREATE != 0 && strings.Contains(p, smbsrv.StreamSeparator) {
		if err := os.MkdirAll(filepath.Dir(full), 0777); err != nil {
			return nil, err
		}
	}
	file, err := osfile.Open(full, flag, 0666)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *Folder) Mkdir(p string) error {
	full, err := f.real(p)
	if err != nil {
		return err
	}
	return os.Mkdir(full, 0777)
}

func (f *Folder) Remove(p string) error {
	full, err := f.real(p)
	if err != nil {
		return err
	}
	isStream := strings.Contains(p, smbsrv.StreamSeparator)
	if fi, err := os.Lstat(full); err == nil && fi.IsDir() && !isStream && !f.cfg.NoStreams {
		//The server checked the folder holds nothing else: the streams kept
		//in it go with it
		os.RemoveAll(filepath.Join(full, f.cfg.InternalFolder))
	}
	if err := os.Remove(full); err != nil {
		return err
	}
	if !isStream {
		f.dropStreams(p)
	}
	return nil
}

func (f *Folder) Rename(oldPath, newPath string) error {
	source, err := f.real(oldPath)
	if err != nil {
		return err
	}
	target, err := f.real(newPath)
	if err != nil {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		return err
	}
	if !strings.EqualFold(oldPath, newPath) && !strings.Contains(oldPath, smbsrv.StreamSeparator) {
		f.moveStreams(oldPath, newPath)
	}
	return nil
}

func (f *Folder) SetModTime(p string, t time.Time) error {
	full, err := f.real(p)
	if err != nil {
		return err
	}
	return os.Chtimes(full, t, t)
}

// Usage reports the size of the disk the folder is on. An unknown size still
// has to look like a usable drive.
func (f *Folder) Usage() (total, free uint64) {
	total, free, err := diskUsage(f.root)
	if err != nil || total == 0 {
		return 1 << 42, 1 << 41
	}
	return total, free
}

// HaveSpace leaves running out of space to the disk, which reports it.
func (f *Folder) HaveSpace(extra int64) bool { return true }

// FileChanged has nothing to keep track of.
func (f *Folder) FileChanged(p string, oldSize, newSize int64) {}

func joinShare(parts ...string) string {
	out := path.Join(parts...)
	if out == "." {
		return ""
	}
	return out
}
