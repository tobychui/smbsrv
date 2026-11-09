package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/tobychui/smbsrv"
	"github.com/tobychui/smbsrv/localfs"
)

/*
	config.go

	The configuration file, smbsrv.json beside the binary unless -c names
	another one. It holds the server settings, the accounts and the shares.

	An account is stored as its NT hash, the MD4 of the password, because
	that is what NTLM logins are checked against: a salted, slow hash would
	make logging in over SMB impossible. The NT hash is enough to log in by
	itself, so the file is written readable by its owner only.
*/

// ConfigFileName is the name of the file kept beside the binary.
const ConfigFileName = "smbsrv.json"

// Config is the whole configuration file.
type Config struct {
	ServerName           string        `json:"serverName"`
	Workgroup            string        `json:"workgroup"`
	Address              string        `json:"address"`
	GUID                 string        `json:"guid"`
	Announce             bool          `json:"announce"`
	RequireEncryption    bool          `json:"requireEncryption"`
	AllowPublicAddresses bool          `json:"allowPublicAddresses"`
	Users                []User        `json:"users"`
	Shares               []ShareConfig `json:"shares"`
}

// User is one account.
type User struct {
	Name    string    `json:"name"`
	NTHash  string    `json:"ntHash"` //Hex of smbsrv.NTHash(password)
	Changed time.Time `json:"changed"`
}

// ShareConfig is one shared folder.
type ShareConfig struct {
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Comment   string   `json:"comment,omitempty"`
	ReadOnly  bool     `json:"readOnly,omitempty"`
	Users     []string `json:"users,omitempty"` //Who may open it; empty is every user
	NoStreams bool     `json:"noStreams,omitempty"`
}

// DefaultConfigPath is smbsrv.json in the folder of the running binary.
func DefaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ConfigFileName
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Join(filepath.Dir(exe), ConfigFileName)
}

// NewConfig returns the settings of a server that has no file yet.
func NewConfig() *Config {
	host, _ := os.Hostname()
	var guid [16]byte
	rand.Read(guid[:])
	return &Config{
		ServerName: netbiosName(host),
		Workgroup:  "WORKGROUP",
		Address:    ":445",
		GUID:       hex.EncodeToString(guid[:]),
		//Windows answers WS-Discovery for itself on the same ports
		Announce: runtime.GOOS != "windows",
		Users:    []User{},
		Shares:   []ShareConfig{},
	}
}

// netbiosName turns a host name into a server name clients accept: up to 15
// letters, digits and hyphens, in capitals.
func netbiosName(host string) string {
	host, _, _ = strings.Cut(host, ".")
	var b strings.Builder
	for _, r := range strings.ToUpper(host) {
		if b.Len() >= 15 {
			break
		}
		if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "SMBSRV"
	}
	return name
}

// LoadConfig reads a configuration file. A missing file gives NewConfig, so
// the first -a or -f creates it.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewConfig(), nil
	}
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Users == nil {
		cfg.Users = []User{}
	}
	if cfg.Shares == nil {
		cfg.Shares = []ShareConfig{}
	}
	return cfg, nil
}

// Validate checks what a hand edited file may have got wrong.
func (c *Config) Validate() error {
	if _, err := c.guid(); err != nil {
		return err
	}
	if c.Address == "" {
		return errors.New("address is empty")
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if err := ValidUsername(u.Name); err != nil {
			return err
		}
		if seen[strings.ToLower(u.Name)] {
			return fmt.Errorf("user %q is listed twice", u.Name)
		}
		seen[strings.ToLower(u.Name)] = true
		if h, err := hex.DecodeString(u.NTHash); err != nil || len(h) != 16 {
			return fmt.Errorf("user %q has no valid ntHash", u.Name)
		}
	}
	names := map[string]bool{}
	for _, s := range c.Shares {
		if err := localfs.ValidShareName(s.Name); err != nil {
			return err
		}
		if names[strings.ToLower(s.Name)] {
			return fmt.Errorf("share %q is listed twice", s.Name)
		}
		names[strings.ToLower(s.Name)] = true
		if s.Path == "" {
			return fmt.Errorf("share %q has no path", s.Name)
		}
	}
	return nil
}

// guid is the stable identity of this server, which clients use to tell
// servers apart.
func (c *Config) guid() ([16]byte, error) {
	var out [16]byte
	b, err := hex.DecodeString(c.GUID)
	if err != nil || len(b) != 16 {
		return out, errors.New("guid must be 32 hex digits")
	}
	copy(out[:], b)
	return out, nil
}

// uuid is the guid in the form WS-Discovery announces.
func (c *Config) uuid() string {
	g, _ := c.guid()
	return fmt.Sprintf("%x-%x-%x-%x-%x", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
}

// Save writes the file through a temporary one, so a crash never leaves half
// a file, readable by its owner only.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ValidUsername accepts 1 to 64 characters without control characters,
// leading or trailing spaces, or any of " / \ [ ] : ; | = , + * ? < > which
// Windows does not allow in an account name.
func ValidUsername(name string) error {
	if name == "" {
		return errors.New("a user name is required")
	}
	if len([]rune(name)) > 64 {
		return errors.New("a user name has at most 64 characters")
	}
	if strings.TrimSpace(name) != name {
		return errors.New("a user name cannot start or end with a space")
	}
	for _, r := range name {
		if unicode.IsControl(r) || strings.ContainsRune(`"/\[]:;|=,+*?<>`, r) {
			return fmt.Errorf("a user name cannot hold %q", r)
		}
	}
	return nil
}

// FindUser looks an account up ignoring case, as Windows does.
func (c *Config) FindUser(name string) *User {
	for i := range c.Users {
		if strings.EqualFold(c.Users[i].Name, name) {
			return &c.Users[i]
		}
	}
	return nil
}

// SetUser adds an account, or sets the password of one that exists. created
// says which happened.
func (c *Config) SetUser(name, password string) (created bool, err error) {
	if err := ValidUsername(name); err != nil {
		return false, err
	}
	if password == "" {
		return false, errors.New("the password is empty")
	}
	hash := hex.EncodeToString(smbsrv.NTHash(password))
	if u := c.FindUser(name); u != nil {
		u.NTHash = hash
		u.Changed = time.Now().UTC().Truncate(time.Second)
		return false, nil
	}
	c.Users = append(c.Users, User{Name: name, NTHash: hash, Changed: time.Now().UTC().Truncate(time.Second)})
	return true, nil
}

// DeleteUser removes an account. Share lists keep the name: dropping it could
// leave a list empty, and an empty list opens the share to everyone.
func (c *Config) DeleteUser(name string) error {
	for i := range c.Users {
		if strings.EqualFold(c.Users[i].Name, name) {
			c.Users = append(c.Users[:i], c.Users[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("there is no user %q", name)
}

// FindShare looks a share up by name, ignoring case.
func (c *Config) FindShare(name string) *ShareConfig {
	for i := range c.Shares {
		if strings.EqualFold(c.Shares[i].Name, name) {
			return &c.Shares[i]
		}
	}
	return nil
}

// AddShare shares a folder and returns the share as stored. An empty name is
// the folder's own name. A share of that name is replaced, which is how its
// settings change; updated says whether one was.
func (c *Config) AddShare(s ShareConfig) (stored ShareConfig, updated bool, err error) {
	if s.Path == "" {
		return s, false, errors.New("a folder is required")
	}
	abs, err := filepath.Abs(s.Path)
	if err != nil {
		return s, false, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return s, false, err
	}
	if !info.IsDir() {
		return s, false, fmt.Errorf("%s is not a folder", abs)
	}
	s.Path = abs
	if s.Name == "" {
		s.Name = filepath.Base(abs)
		if localfs.ValidShareName(s.Name) != nil || s.Name == "." || s.Name == string(filepath.Separator) {
			return s, false, fmt.Errorf("%s has no name to share it under, give one with -n", abs)
		}
	}
	if err := localfs.ValidShareName(s.Name); err != nil {
		return s, false, err
	}
	users := []string{}
	for _, u := range s.Users {
		if u = strings.TrimSpace(u); u != "" {
			users = append(users, u)
		}
	}
	s.Users = users
	if old := c.FindShare(s.Name); old != nil {
		*old = s
		return s, true, nil
	}
	c.Shares = append(c.Shares, s)
	return s, false, nil
}

// RemoveShare stops sharing a folder. The folder itself is not touched.
func (c *Config) RemoveShare(name string) error {
	for i := range c.Shares {
		if strings.EqualFold(c.Shares[i].Name, name) {
			c.Shares = append(c.Shares[:i], c.Shares[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("there is no share %q", name)
}

// Allows reports whether a user may open the share.
func (s ShareConfig) Allows(username string) bool {
	if len(s.Users) == 0 {
		return true
	}
	for _, u := range s.Users {
		if strings.EqualFold(u, username) {
			return true
		}
	}
	return false
}
