package localfs

import (
	"errors"
	"net"
	"time"

	"github.com/tobychui/smbsrv"
)

// Options configures a Backend.
type Options struct {
	//Lookup finds an account: the real spelling of its name and its NT hash
	//(see smbsrv.NTHash). Names arrive as the client typed them, so match
	//them ignoring case. Required.
	Lookup func(username string) (name string, ntHash []byte, ok bool)

	//Shares lists what a logged in user may open. It is asked on every tree
	//connect, so a changed list applies from the next one. Required.
	Shares func(username string) []smbsrv.Share

	//AllowPublicAddresses lets clients from outside private, loopback and
	//link-local networks connect. SMB must not face the internet, so this is
	//off unless asked for.
	AllowPublicAddresses bool

	//AllowIP is asked after the private network rule; nil allows every
	//address that passed it
	AllowIP func(ip net.IP) bool

	//OnAuth is told of every login attempt. Optional.
	OnAuth func(username, remote string, ok bool)

	//FailureDelay holds back the reply to a failed login. Zero leaves it to
	//smbsrv.Config.LoginDelay.
	FailureDelay time.Duration
}

// Backend is a smbsrv.Backend over accounts and shares that Options supplies.
type Backend struct {
	opt Options
}

// NewBackend checks the options and returns a Backend.
func NewBackend(opt Options) (*Backend, error) {
	if opt.Lookup == nil || opt.Shares == nil {
		return nil, errors.New("localfs: Lookup and Shares are required")
	}
	return &Backend{opt: opt}, nil
}

// LookupHash implements smbsrv.Backend.
func (b *Backend) LookupHash(username string) (string, []byte, bool) {
	name, hash, ok := b.opt.Lookup(username)
	if !ok || len(hash) != 16 {
		return "", nil, false
	}
	return name, hash, true
}

// Login implements smbsrv.Backend.
func (b *Backend) Login(username string) (smbsrv.UserView, error) {
	return &view{username: username, shares: b.opt.Shares}, nil
}

// Allow implements smbsrv.Backend.
func (b *Backend) Allow(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if !b.opt.AllowPublicAddresses && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
		return false
	}
	if b.opt.AllowIP != nil {
		return b.opt.AllowIP(ip)
	}
	return true
}

// AuthLog implements smbsrv.Backend.
func (b *Backend) AuthLog(username, remote string, ok bool) time.Duration {
	if b.opt.OnAuth != nil {
		b.opt.OnAuth(username, remote, ok)
	}
	if ok {
		return 0
	}
	return b.opt.FailureDelay
}

type view struct {
	username string
	shares   func(username string) []smbsrv.Share
}

func (v *view) Username() string { return v.username }

func (v *view) Shares() []smbsrv.Share { return v.shares(v.username) }
