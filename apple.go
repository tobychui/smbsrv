package smbsrv

import (
	"encoding/binary"
	"os"
	"strings"
	"time"

	"github.com/tobychui/smbsrv/internal/wire"
)

/*
	apple.go

	The AAPL create context. macOS sends it with its first open on a share and
	the server answers with the Apple extensions it supports:

	- Unix based: macOS then treats the server as a Unix one rather than a
	  Windows one.
	- Finder info in listings (READ_DIR_ATTR): FILE_ID_BOTH_DIR_INFORMATION
	  entries carry the access mask, the resource fork size and the compressed
	  Finder info, so Finder need not open the AFP_AfpInfo stream of every
	  file it shows.
	- Full sync, on shares that take Time Machine backups (TimeMachineShare).
	  macOS only backs up to a network share that offers it.

	Clients that sent the context get zero file ids, as Samba and ksmbd give
	them: macOS takes a non zero id for an inode number that survives a
	rename, which a path hash does not.

	The layout is the one Apple's smbfs client reads, and Samba (vfs_fruit)
	and ksmbd answer. Copying a whole file with its streams (OSX_COPYFILE) and
	NFS ACEs are not offered, as in Samba's defaults.
*/

// AAPL command codes, request bits and capability bits.
const (
	appleServerQuery = 1

	appleWantServerCaps = 1
	appleWantVolumeCaps = 2
	appleWantModelInfo  = 4

	appleReadDirAttr = 1
	appleUnixBased   = 4

	appleVolumeFullSync = 4
)

// Stream names macOS keeps Finder info and resource forks in.
const (
	AppleInfoStream     = "AFP_AfpInfo"
	AppleResourceStream = "AFP_Resource"
)

// DefaultAppleModel is the model macOS is told when Config.AppleModel is
// empty. It picks the icon Finder shows for the server.
const DefaultAppleModel = "RackMac"

// appleDateUnknown is the Finder date of a file that has none: the earliest
// date AFP can hold, as a signed count of seconds from 2000.
const appleDateUnknown = 0x80000000

// appleEpoch is 2000-01-01, where AFP dates start, in Unix seconds.
const appleEpoch = 946684800

// TimeMachineShare is a Share macOS may back up to with Time Machine. With
// Config.Apple on, a share whose TimeMachine reports on is offered with full
// sync, which macOS requires of a network backup disk. With maxSize set, the
// share reports at most maxSize, less what the Time Machine bundles
// (.sparsebundle and .backupbundle folders) at its root already take, so Time
// Machine removes old backups at the limit instead of filling the drive.
type TimeMachineShare interface {
	TimeMachine() (on bool, maxSize uint64)
}

func timeMachine(s Share) (bool, uint64) {
	if t, ok := s.(TimeMachineShare); ok {
		return t.TimeMachine()
	}
	return false, 0
}

// appleListing is how a connection wants directory entries filled in.
type appleListing struct {
	zeroIDs bool //The client sent AAPL
	dirAttr bool //It also takes Finder info in listings
}

func (c *conn) appleListing() appleListing {
	c.mu.Lock()
	defer c.mu.Unlock()
	return appleListing{zeroIDs: c.apple, dirAttr: c.appleDirAttr}
}

// fileID is the file id a client is shown.
func (c *conn) fileID(s Share, p string, info FileInfo) uint64 {
	if c.appleListing().zeroIDs {
		return 0
	}
	return fileNumber(s, p, info)
}

// appleReply answers an AAPL server query on share, or returns nil for one
// this server does not answer: Apple support off, a short context, or another
// command such as resolving a file id.
func (c *conn) appleReply(share Share, data []byte) []byte {
	if !c.srv.cfg.Apple {
		return nil
	}
	r := wire.NewReader(data)
	cmd := r.U32()
	r.Skip(4)
	want := r.U64()
	clientCaps := r.U64()
	if r.Bad() || cmd != appleServerQuery {
		return nil
	}
	want &= appleWantServerCaps | appleWantVolumeCaps | appleWantModelInfo

	w := wire.NewWriter(96)
	w.U32(appleServerQuery)
	w.U32(0)
	w.U64(want)
	dirAttr := false
	if want&appleWantServerCaps != 0 {
		caps := uint64(appleUnixBased)
		if clientCaps&appleReadDirAttr != 0 {
			caps |= appleReadDirAttr
			dirAttr = true
		}
		w.U64(caps)
	}
	if want&appleWantVolumeCaps != 0 {
		var caps uint64
		if on, _ := timeMachine(share); on {
			caps |= appleVolumeFullSync
		}
		w.U64(caps)
	}
	if want&appleWantModelInfo != 0 {
		//Leaving the model out when it was asked for breaks the macOS client
		model := wire.EncodeUTF16(c.srv.cfg.AppleModel)
		w.U32(0)
		w.U32(uint32(len(model)))
		w.Bytes(model)
	}

	c.mu.Lock()
	c.apple = true
	if dirAttr {
		c.appleDirAttr = true
	}
	c.mu.Unlock()
	return w.B
}

// appleShortName is what an AAPL client reads in place of the short name of a
// FILE_ID_BOTH_DIR_INFORMATION entry: a length of 24, then the resource fork
// size and the compressed Finder info.
func appleShortName(s Share, e *dirEntry) []byte {
	b := make([]byte, 2+24)
	b[0] = 24
	finder := b[10:26]
	binary.BigEndian.PutUint32(finder[12:], appleDateUnknown)

	ss, ok := s.(StreamShare)
	if !ok {
		return b
	}
	hasInfo := false
	for _, st := range ss.Streams(e.path) {
		switch {
		case strings.EqualFold(st.Name, AppleResourceStream):
			binary.LittleEndian.PutUint64(b[2:], uint64(st.Size))
		case strings.EqualFold(st.Name, AppleInfoStream):
			hasInfo = true
		}
	}
	if !hasInfo {
		return b
	}
	info, ok := readFinderInfo(s, e.path)
	if !ok {
		return b
	}
	//Type and creator belong to files only
	if !e.info.IsDir {
		copy(finder[0:8], info[0:8])
	}
	copy(finder[8:10], info[8:10])   //Finder flags
	copy(finder[10:12], info[24:26]) //Extended flags
	added := birthOf(e.info).Unix() - appleEpoch
	binary.BigEndian.PutUint32(finder[12:], uint32(int32(added)))
	return b
}

// readFinderInfo returns the 32 bytes of Finder info in the AFP_AfpInfo
// stream of p: a 60 byte record starting "AFP\0", Finder info at offset 16.
func readFinderInfo(s Share, p string) ([]byte, bool) {
	f, err := s.Open(streamPath(p, AppleInfoStream), os.O_RDONLY)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, 60)
	n, _ := f.ReadAt(buf, 0)
	if n < 48 || string(buf[0:4]) != "AFP\x00" {
		return nil, false
	}
	return buf[16:48], true
}

// timeMachineUsageTTL is how long the size of a share's backups is reused.
// Walking a backup bundle lists every band file in it.
var timeMachineUsageTTL = 30 * time.Second

type timeMachineUsage struct {
	used uint64
	at   time.Time
}

// usage is the size and free space a client is shown for a share. A Time
// Machine share with a size limit shows the limit, less its backups.
func (s *Server) usage(share Share) (total, free uint64) {
	total, free = share.Usage()
	if !s.cfg.Apple {
		return total, free
	}
	on, limit := timeMachine(share)
	if !on || limit == 0 {
		return total, free
	}
	used := s.timeMachineUsed(share)
	left := uint64(0)
	if used < limit {
		left = limit - used
	}
	if limit < total {
		total = limit
	}
	if left < free {
		free = left
	}
	return total, free
}

func (s *Server) timeMachineUsed(share Share) uint64 {
	key := share.Key()
	s.tmMu.Lock()
	if u, ok := s.tmUsage[key]; ok && time.Since(u.at) < timeMachineUsageTTL {
		s.tmMu.Unlock()
		return u.used
	}
	s.tmMu.Unlock()

	used := backupBundleSize(share)
	s.tmMu.Lock()
	if s.tmUsage == nil {
		s.tmUsage = map[string]timeMachineUsage{}
	}
	s.tmUsage[key] = timeMachineUsage{used: used, at: time.Now()}
	s.tmMu.Unlock()
	return used
}

// isBackupBundle reports a folder Time Machine keeps a computer's backups in.
func isBackupBundle(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".sparsebundle") || strings.HasSuffix(lower, ".backupbundle")
}

// backupBundleSize adds up the files in the backup bundles at a share's root.
func backupBundleSize(share Share) uint64 {
	list, err := share.ReadDir("")
	if err != nil {
		return 0
	}
	var total uint64
	for _, e := range list {
		if e.IsDir && isBackupBundle(e.Name) {
			total += treeSize(share, e.Name, 0)
		}
	}
	return total
}

// treeSize adds up the files below p. A bundle is a few levels deep, so the
// walk stops at a depth no bundle reaches, in case of a loop.
func treeSize(share Share, p string, depth int) uint64 {
	if depth > 16 {
		return 0
	}
	list, err := share.ReadDir(p)
	if err != nil {
		return 0
	}
	var total uint64
	for _, e := range list {
		if isInternal(share, e.Name) {
			continue
		}
		if e.IsDir {
			total += treeSize(share, joinPath(p, e.Name), depth+1)
		} else if e.Size > 0 {
			total += uint64(e.Size)
		}
	}
	return total
}
