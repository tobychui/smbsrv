package smbsrv

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tobychui/smbsrv/internal/wire"
)

// appleQuery is the AAPL server query macOS sends with its first open.
func appleQuery(cmd uint32, want, clientCaps uint64) createCtx {
	w := wire.NewWriter(24)
	w.U32(cmd)
	w.U32(0)
	w.U64(want)
	w.U64(clientCaps)
	return createCtx{wire.ContextApple, w.B}
}

// macOSQuery is what macOS asks for: everything, with Finder info in
// listings (client caps 0x07: read dir attr, copyfile, unix based).
func macOSQuery() createCtx { return appleQuery(appleServerQuery, 7, 7) }

var openRoot = createOpts{access: wire.FileReadData | wire.FileReadAttributes, share: shareAll, disposition: wire.DispositionOpen, options: wire.OptionDirectory}

// contextData returns the data of one create context of a CREATE response.
func contextData(t *testing.T, r rawReply, name string) ([]byte, bool) {
	t.Helper()
	if r.hdr.Status != 0 {
		t.Fatalf("create: %x", r.hdr.Status)
	}
	off := int(binary.LittleEndian.Uint32(r.body[80:]))
	n := int(binary.LittleEndian.Uint32(r.body[84:]))
	if n == 0 {
		return nil, false
	}
	chain := r.body[off-wire.HeaderSize : off-wire.HeaderSize+n]
	for {
		next := binary.LittleEndian.Uint32(chain)
		nameOff := binary.LittleEndian.Uint16(chain[4:])
		nameLen := binary.LittleEndian.Uint16(chain[6:])
		dataOff := binary.LittleEndian.Uint16(chain[10:])
		dataLen := binary.LittleEndian.Uint32(chain[12:])
		if string(chain[nameOff:nameOff+nameLen]) == name {
			return chain[dataOff : uint32(dataOff)+dataLen], true
		}
		if next == 0 {
			return nil, false
		}
		chain = chain[next:]
	}
}

// appleOpen opens the share root with an AAPL context and returns the reply.
func appleOpen(t *testing.T, c *rawClient, q createCtx) (wire.FileID, []byte, bool) {
	t.Helper()
	r := c.call(wire.CmdCreate, createWithContexts("", openRoot, 0, []createCtx{q}))
	var id wire.FileID
	copy(id[:], r.body[64:80])
	data, ok := contextData(t, r, wire.ContextApple)
	return id, data, ok
}

func withApple(cfg *Config) { cfg.Apple = true }

func TestAppleIsOffByDefault(t *testing.T) {
	h := newHarness(t)
	c := newRawClient(t, h)
	if _, _, ok := appleOpen(t, c, macOSQuery()); ok {
		t.Error("answered AAPL with Apple support off")
	}
}

// TestAppleServerQuery checks the reply layout: command, reserved, the
// request bits answered, then only the fields asked for, in order.
func TestAppleServerQuery(t *testing.T) {
	model := wire.EncodeUTF16(DefaultAppleModel)
	modelPart := append([]byte{0, 0, 0, 0, byte(len(model)), 0, 0, 0}, model...)
	u64 := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		return b
	}
	head := func(want uint64) []byte { return append([]byte{1, 0, 0, 0, 0, 0, 0, 0}, u64(want)...) }
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	tests := []struct {
		name        string
		query       createCtx
		timeMachine bool
		want        []byte //nil: no AAPL reply
	}{
		{"macOS", macOSQuery(), false, join(head(7), u64(appleUnixBased|appleReadDirAttr), u64(0), modelPart)},
		{"time machine share", macOSQuery(), true, join(head(7), u64(appleUnixBased|appleReadDirAttr), u64(appleVolumeFullSync), modelPart)},
		{"no finder info", appleQuery(1, 7, 4), false, join(head(7), u64(appleUnixBased), u64(0), modelPart)},
		{"server caps only", appleQuery(1, 1, 7), false, join(head(1), u64(appleUnixBased|appleReadDirAttr))},
		{"volume caps only", appleQuery(1, 2, 7), true, join(head(2), u64(appleVolumeFullSync))},
		{"unknown bits dropped", appleQuery(1, 0xff, 0), false, join(head(7), u64(appleUnixBased), u64(0), modelPart)},
		{"resolve id is not answered", appleQuery(2, 7, 7), false, nil},
		{"short context", createCtx{wire.ContextApple, []byte{1, 0, 0, 0}}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, withApple)
			h.share.tmOn = tt.timeMachine
			c := newRawClient(t, h)
			_, got, ok := appleOpen(t, c, tt.query)
			if tt.want == nil {
				if ok {
					t.Fatalf("answered: %x", got)
				}
				return
			}
			if !ok {
				t.Fatal("no AAPL reply")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("reply\n got %x\nwant %x", got, tt.want)
			}
		})
	}
}

func TestAppleModelIsConfigurable(t *testing.T) {
	h := newHarness(t, withApple, func(cfg *Config) { cfg.AppleModel = "Xserve" })
	c := newRawClient(t, h)
	_, got, _ := appleOpen(t, c, macOSQuery())
	if !bytes.HasSuffix(got, wire.EncodeUTF16("Xserve")) {
		t.Errorf("model not sent: %x", got)
	}
}

// listEntry is one FILE_ID_BOTH_DIR_INFORMATION entry.
type listEntry struct {
	eaSize    uint32
	shortLen  uint8
	shortName []byte
	reserved2 uint16
	fileID    uint64
}

func listing(t *testing.T, c *rawClient, id wire.FileID) map[string]listEntry {
	t.Helper()
	r := c.call(wire.CmdQueryDirectory, queryDirBody(id, wire.FileIdBothDirectoryInformation, 0, "*"))
	if r.hdr.Status != 0 {
		t.Fatalf("query directory: %x", r.hdr.Status)
	}
	buf := r.body[8:]
	out := map[string]listEntry{}
	for {
		nameLen := binary.LittleEndian.Uint32(buf[60:])
		name, _ := wire.DecodeUTF16(buf[104 : 104+nameLen])
		out[name] = listEntry{
			eaSize:    binary.LittleEndian.Uint32(buf[64:]),
			shortLen:  buf[68],
			shortName: append([]byte{}, buf[70:94]...),
			reserved2: binary.LittleEndian.Uint16(buf[94:]),
			fileID:    binary.LittleEndian.Uint64(buf[96:]),
		}
		next := binary.LittleEndian.Uint32(buf)
		if next == 0 {
			return out
		}
		buf = buf[next:]
	}
}

// afpInfo is an AFP_AfpInfo stream holding finder as its Finder info.
func afpInfo(finder []byte) []byte {
	b := make([]byte, 60)
	copy(b, "AFP\x00")
	b[6] = 1 //Version 1.0
	copy(b[16:], finder)
	return b
}

func TestAppleFinderInfoInListings(t *testing.T) {
	h := newHarness(t, withApple)
	root := h.share.root
	birth := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	os.WriteFile(filepath.Join(root, "doc.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(root, "plain.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(root, "locked.txt"), []byte("x"), 0644)
	os.Mkdir(filepath.Join(root, "folder"), 0755)
	for _, name := range []string{"doc.txt", "folder"} {
		os.Chtimes(filepath.Join(root, name), birth, birth)
	}
	h.share.denyWrite["locked.txt"] = true

	//Type TEXT, creator ttxt, flags 0x0102, extended flags 0x0304 at 24
	finder := make([]byte, 32)
	copy(finder, "TEXTttxt")
	finder[8], finder[9] = 0x01, 0x02
	finder[24], finder[25] = 0x03, 0x04
	streams := filepath.Join(root, ".streams")
	os.Mkdir(streams, 0755)
	os.WriteFile(filepath.Join(streams, "doc.txt~AFP_AfpInfo"), afpInfo(finder), 0644)
	os.WriteFile(filepath.Join(streams, "doc.txt~AFP_Resource"), make([]byte, 300), 0644)
	os.WriteFile(filepath.Join(streams, "folder~AFP_AfpInfo"), afpInfo(finder), 0644)

	c := newRawClient(t, h)
	id, _, _ := appleOpen(t, c, macOSQuery())
	got := listing(t, c, id)

	date := make([]byte, 4)
	binary.BigEndian.PutUint32(date, uint32(birth.Unix()-appleEpoch))
	unknown := []byte{0x80, 0, 0, 0}
	rfork := func(n uint64) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, n)
		return b
	}
	tests := []struct {
		name   string
		access uint32
		short  []byte
	}{
		{"doc.txt", wire.FileAllAccess, bytes.Join([][]byte{rfork(300), []byte("TEXTttxt"), {1, 2, 3, 4}, date}, nil)},
		{"folder", wire.FileAllAccess, bytes.Join([][]byte{rfork(0), make([]byte, 8), {1, 2, 3, 4}, date}, nil)},
		{"plain.txt", wire.FileAllAccess, bytes.Join([][]byte{rfork(0), make([]byte, 12), unknown}, nil)},
		{"locked.txt", wire.ReadOnlyAccess, bytes.Join([][]byte{rfork(0), make([]byte, 12), unknown}, nil)},
	}
	for _, tt := range tests {
		e, ok := got[tt.name]
		if !ok {
			t.Errorf("%s missing from the listing", tt.name)
			continue
		}
		if e.eaSize != tt.access {
			t.Errorf("%s: access %x, want %x", tt.name, e.eaSize, tt.access)
		}
		if e.shortLen != 24 {
			t.Errorf("%s: short name length %d, want 24", tt.name, e.shortLen)
		}
		if !bytes.Equal(e.shortName, tt.short) {
			t.Errorf("%s: short name\n got %x\nwant %x", tt.name, e.shortName, tt.short)
		}
		if e.reserved2 != 0 || e.fileID != 0 {
			t.Errorf("%s: mode %o id %x, want both zero", tt.name, e.reserved2, e.fileID)
		}
	}
}

// TestListingsWithoutApple checks that a client that sent no AAPL context,
// or one with Finder info turned down, sees the usual entries.
func TestListingsWithoutApple(t *testing.T) {
	tests := []struct {
		name    string
		query   *createCtx
		wantIDs bool //File ids are real
	}{
		{"no AAPL", nil, true},
		{"AAPL without finder info", &createCtx{wire.ContextApple, appleQuery(1, 7, 4).data}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, withApple)
			os.WriteFile(filepath.Join(h.share.root, "a.txt"), []byte("a"), 0644)
			c := newRawClient(t, h)
			var id wire.FileID
			if tt.query == nil {
				id, _ = c.create("", openRoot)
			} else {
				id, _, _ = appleOpen(t, c, *tt.query)
			}
			e := listing(t, c, id)["a.txt"]
			if e.eaSize != 0 || e.shortLen != 0 || !bytes.Equal(e.shortName, make([]byte, 24)) {
				t.Errorf("finder info sent: %+v", e)
			}
			if (e.fileID != 0) != tt.wantIDs {
				t.Errorf("file id %x, want real ids %v", e.fileID, tt.wantIDs)
			}
		})
	}
}

func TestAppleClientsGetZeroFileIDs(t *testing.T) {
	for _, apple := range []bool{false, true} {
		h := newHarness(t, withApple)
		os.WriteFile(filepath.Join(h.share.root, "a.txt"), []byte("a"), 0644)
		c := newRawClient(t, h)
		if apple {
			appleOpen(t, c, macOSQuery())
		}
		id, st := c.create("a.txt", createOpts{access: wire.FileReadAttributes, share: shareAll, disposition: wire.DispositionOpen})
		if st != 0 {
			t.Fatalf("open: %x", st)
		}
		for _, class := range []uint8{wire.FileInternalInformation, wire.FileAllInformation} {
			r := c.call(wire.CmdQueryInfo, queryInfoBody(id, wire.InfoFile, class, 0))
			if r.hdr.Status != 0 {
				t.Fatalf("query %d: %x", class, r.hdr.Status)
			}
			data := r.body[8:]
			at := 0
			if class == wire.FileAllInformation {
				at = 40 + 24 //Basic, then standard information
			}
			fileID := binary.LittleEndian.Uint64(data[at:])
			if (fileID == 0) != apple {
				t.Errorf("AAPL %v, class %d: file id %x", apple, class, fileID)
			}
		}
	}
}

func TestIsBackupBundle(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"MacBook.sparsebundle", true},
		{"MacBook.SparseBundle", true},
		{"MacBook.backupbundle", true},
		{"Backups.backupdb", false},
		{"sparsebundle", false},
		{"photos", false},
	}
	for _, tt := range tests {
		if got := isBackupBundle(tt.name); got != tt.want {
			t.Errorf("isBackupBundle(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestTimeMachineSizeLimit checks the size a Time Machine share reports:
// the limit, less the backup bundles at its root and nothing else.
func TestTimeMachineSizeLimit(t *testing.T) {
	const mib = 1 << 20
	tests := []struct {
		name      string
		apple     bool
		tmOn      bool
		limit     uint64
		bundle    int64
		wantTotal uint64
		wantFree  uint64
	}{
		{"limit less backups", true, true, 100 * mib, 30 * mib, 100 * mib, 70 * mib},
		{"backups over the limit", true, true, 100 * mib, 150 * mib, 100 * mib, 0},
		{"no limit", true, true, 0, 30 * mib, 1 << 40, 1 << 39},
		{"not a Time Machine share", true, false, 100 * mib, 30 * mib, 1 << 40, 1 << 39},
		{"Apple support off", false, true, 100 * mib, 30 * mib, 1 << 40, 1 << 39},
		{"limit over the drive", true, true, 1 << 41, 0, 1 << 40, 1 << 39},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config) { cfg.Apple = tt.apple })
			h.share.tmOn, h.share.tmMax = tt.tmOn, tt.limit
			root := h.share.root
			bands := filepath.Join(root, "Mac.sparsebundle", "bands")
			os.MkdirAll(bands, 0755)
			os.WriteFile(filepath.Join(root, "Mac.sparsebundle", "Info.plist"), make([]byte, 1000), 0644)
			if tt.bundle > 0 {
				f, _ := os.Create(filepath.Join(bands, "0"))
				f.Truncate(tt.bundle - 1000) //Sparse, takes no disk
				f.Close()
			}
			//Other files of the share do not count
			f, _ := os.Create(filepath.Join(root, "movie.mov"))
			f.Truncate(500 * mib)
			f.Close()

			c := newRawClient(t, h)
			id, st := c.create("", openRoot)
			if st != 0 {
				t.Fatalf("open: %x", st)
			}
			r := c.call(wire.CmdQueryInfo, queryInfoBody(id, wire.InfoFilesystem, wire.FileFsFullSizeInformation, 0))
			if r.hdr.Status != 0 {
				t.Fatalf("query: %x", r.hdr.Status)
			}
			data := r.body[8:]
			total := binary.LittleEndian.Uint64(data) * clusterSize
			free := binary.LittleEndian.Uint64(data[8:]) * clusterSize
			if total != tt.wantTotal || free != tt.wantFree {
				t.Errorf("total %d free %d, want %d and %d", total, free, tt.wantTotal, tt.wantFree)
			}
		})
	}
}

// TestTimeMachineUsageIsCached checks the bundles are walked once per TTL:
// Finder asks for the free space all the time.
func TestTimeMachineUsageIsCached(t *testing.T) {
	h := newHarness(t, withApple)
	h.share.tmOn, h.share.tmMax = true, 1<<30
	bundle := filepath.Join(h.share.root, "Mac.sparsebundle")
	os.Mkdir(bundle, 0755)
	os.WriteFile(filepath.Join(bundle, "a"), make([]byte, 100), 0644)
	if got := h.srv.timeMachineUsed(h.share); got != 100 {
		t.Fatalf("used %d, want 100", got)
	}
	os.WriteFile(filepath.Join(bundle, "b"), make([]byte, 100), 0644)
	if got := h.srv.timeMachineUsed(h.share); got != 100 {
		t.Errorf("used %d within the TTL, want the cached 100", got)
	}
	old := timeMachineUsageTTL
	timeMachineUsageTTL = 0
	defer func() { timeMachineUsageTTL = old }()
	if got := h.srv.timeMachineUsed(h.share); got != 200 {
		t.Errorf("used %d after the TTL, want 200", got)
	}
}
