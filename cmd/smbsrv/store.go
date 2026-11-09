package main

import (
	"encoding/hex"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/tobychui/smbsrv"
	"github.com/tobychui/smbsrv/localfs"
)

/*
	store.go

	What a running server reads its accounts and shares from. The file is
	looked at again, at most once a second, whenever a client logs in or opens
	a share, so smbsrv -a and -f take effect without a restart. Server
	settings (address, name, encryption) are read once at start.
*/

// reloadInterval is a variable so tests can look at the file every time.
var reloadInterval = time.Second

type store struct {
	path   string
	logger *slog.Logger

	//onReload runs after a changed file was read, with the old and new
	//settings, outside the lock
	onReload func(old, cur *Config)

	mu      sync.Mutex
	cfg     *Config
	modTime time.Time
	size    int64
	checked time.Time
}

func newStore(path string, cfg *Config, logger *slog.Logger) *store {
	s := &store{path: path, cfg: cfg, logger: logger, checked: time.Now()}
	if fi, err := os.Stat(path); err == nil {
		s.modTime, s.size = fi.ModTime(), fi.Size()
	}
	return s
}

// current returns the settings, read again if the file changed.
func (s *store) current() *Config {
	s.mu.Lock()
	if time.Since(s.checked) < reloadInterval {
		cfg := s.cfg
		s.mu.Unlock()
		return cfg
	}
	s.checked = time.Now()
	fi, err := os.Stat(s.path)
	if err != nil || (fi.ModTime().Equal(s.modTime) && fi.Size() == s.size) {
		cfg := s.cfg
		s.mu.Unlock()
		return cfg
	}
	s.modTime, s.size = fi.ModTime(), fi.Size()
	cfg, err := LoadConfig(s.path)
	if err != nil {
		s.logger.Warn("The changed configuration file could not be read, the old settings stay", "err", err)
		cfg := s.cfg
		s.mu.Unlock()
		return cfg
	}
	old := s.cfg
	s.cfg = cfg
	s.mu.Unlock()

	s.logger.Info("Read the changed configuration file", "users", len(cfg.Users), "shares", len(cfg.Shares))
	if s.onReload != nil {
		s.onReload(old, cfg)
	}
	return cfg
}

// lookup implements localfs.Options.Lookup.
func (s *store) lookup(username string) (string, []byte, bool) {
	u := s.current().FindUser(username)
	if u == nil {
		return "", nil, false
	}
	hash, err := hex.DecodeString(u.NTHash)
	if err != nil || len(hash) != 16 {
		return "", nil, false
	}
	return u.Name, hash, true
}

// shares implements localfs.Options.Shares: the folders this user may open.
func (s *store) shares(username string) []smbsrv.Share {
	cfg := s.current()
	out := []smbsrv.Share{}
	for _, sc := range cfg.Shares {
		if !sc.Allows(username) {
			continue
		}
		share, err := localfs.New(localfs.Config{
			Name:      sc.Name,
			Path:      sc.Path,
			Comment:   sc.Comment,
			ReadOnly:  sc.ReadOnly,
			NoStreams: sc.NoStreams,
		})
		if err != nil {
			s.logger.Warn("Share "+sc.Name+" is not available", "err", err)
			continue
		}
		out = append(out, share)
	}
	return out
}

// changedUsers lists the accounts of old that are gone from cur or have
// another password, whose open sessions should end.
func changedUsers(old, cur *Config) []string {
	out := []string{}
	for _, u := range old.Users {
		now := cur.FindUser(u.Name)
		if now == nil || now.NTHash != u.NTHash {
			out = append(out, u.Name)
		}
	}
	return out
}
