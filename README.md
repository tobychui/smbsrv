# smbsrv

An SMB 2.1 to 3.1.1 file server in pure Go: a library you can embed, and a
single binary server built on it. No Samba, no cgo, no external tools.

It was written for [ArozOS](https://github.com/tobychui/arozos) so Windows
Explorer could open its drives, and has been used there with Windows, macOS
and Linux clients.

- Dialects 2.1, 3.0, 3.0.2 and 3.1.1, with pre-auth integrity
- NTLMv2 logins over SPNEGO
- Signing (HMAC-SHA256, AES-CMAC, AES-GMAC) and encryption (AES-128/256 in
  CCM and GCM), optionally required
- Leases and durable handles, so clients can cache and survive a dropped
  connection
- Change notifications, byte range locks, share modes, server side copy
- Named streams (Zone.Identifier, Finder tags and resource forks of macOS)
- Previous Versions, for backends that keep snapshots
- Share listing over IPC$ (srvsvc, lsarpc, wkssvc), and optional WS-Discovery
  so the server shows in the Windows Network view

## The smbsrv command

### Build

```bash
go install github.com/tobychui/smbsrv/cmd/smbsrv@latest
```

or from a checkout:

```bash
go build -o smbsrv ./cmd/smbsrv
```

It cross-compiles like any Go program, for example
`GOOS=linux GOARCH=arm64 go build ./cmd/smbsrv` for a Raspberry Pi.

### Quick start

```bash
smbsrv -a alice -pw "very_secure_password"   # add a user
smbsrv -f /srv/photos                         # share a folder, as "photos"
smbsrv                                        # start the server
```

Then open `\\HOST\photos` in Windows Explorer, `smb://HOST/photos` in the macOS
Finder, or on Linux:

```bash
smbclient //HOST/photos -U alice
```

Users and shares can be changed while the server runs: it reads the file again
when a client logs in or opens a share, and logs out the sessions of an account
that was deleted or got a new password.

### Options

| Command | What it does |
| --- | --- |
| `smbsrv -a NAME [-pw PASSWORD]` | Add a user, or change their password. Without `-pw` the password is asked for (twice, hidden), or read as one line from piped input, which keeps it out of your shell history. |
| `smbsrv -d NAME` | Delete a user. |
| `smbsrv -f FOLDER` | Share a folder. Run it again for the same share to change its settings. |
| `  -n NAME` | Share name (default: the folder's name). |
| `  -ro` | Read only. |
| `  -u alice,bob` | Only these users may open it (default: every user). |
| `  -nostreams` | Keep no named streams for this share (see below). |
| `smbsrv -rm NAME` | Stop sharing a folder. The folder is not touched. |
| `smbsrv -l` | List users and shares. |
| `smbsrv` | Start the server. |
| `  -addr :1445` | Listen address for this run. |
| `  -name NAS` | Server name for this run. |
| `  -announce` | Show the server in the Windows Network view (WS-Discovery and LLMNR). Only useful on port 445. |
| `  -encrypt` | Refuse clients that cannot encrypt (SMB 2.1, and 3.x with encryption turned off). |
| `  -capture DIR` | Write a pcap and a trace log of every connection, for debugging. NTLM responses are blanked. |
| `-c FILE` | Use another settings file. |

### The settings file

Everything lives in `smbsrv.json` beside the binary (or the file `-c` names).
It is created by the first `-a` or `-f`:

```json
{
  "serverName": "NAS",
  "workgroup": "WORKGROUP",
  "address": ":445",
  "guid": "5f0c2d8e9a7b4c1d8e2f3a4b5c6d7e8f",
  "announce": true,
  "requireEncryption": false,
  "allowPublicAddresses": false,
  "users": [
    { "name": "alice", "ntHash": "8846f7eaee8fb117ad06bdd830b7586c", "changed": "2026-11-09T10:00:00Z" }
  ],
  "shares": [
    { "name": "photos", "path": "/srv/photos" },
    { "name": "archive", "path": "/srv/archive", "readOnly": true, "users": ["alice"] }
  ]
}
```

Server settings (`address`, `serverName`, `announce`, `requireEncryption`,
`allowPublicAddresses`) are read when the server starts; edit them by hand and
restart. `guid` identifies the server to clients and is made once.

**About the password hash.** NTLM, the login every SMB client offers, is
checked against the NT hash: an unsalted MD4 of the password. The server has to
keep exactly that, so a salted, slow hash such as bcrypt is not an option. The
NT hash is enough to log in by itself, so treat the file like a password file:
smbsrv writes it readable by its owner only. This is a demonstration of the
library; a real deployment would keep the hashes somewhere safer, which is a
matter of implementing `LookupHash`.

### Ports and permissions

SMB clients connect to port 445.

- **Linux**: ports below 1024 need root. Either run as root, or allow the
  binary once: `sudo setcap cap_net_bind_service=+ep ./smbsrv`. Samba, if
  installed, already holds 445.
- **macOS**: turn off the built-in File Sharing first, which holds 445.
- **Windows**: Windows keeps 445 for its own file sharing. Run smbsrv on another
  port (`-addr :1445`); Windows 11 24H2 and newer clients can reach it with
  `net use \\HOST\share /TCPPORT:1445`, macOS with `smb://HOST:1445/share`,
  Linux with `smbclient -p 1445` or `mount -t cifs -o port=1445`.

By default only clients from private, loopback and link-local addresses are
let in. **Never expose SMB to the internet.**

### Named streams

Clients attach small named streams to files: Windows marks downloaded files
with `Zone.Identifier`, macOS keeps Finder tags, labels and resource forks in
them. smbsrv keeps them as files in a hidden `.smbsrv` folder beside the files
they belong to, which works on every file system. The folder never shows over
SMB. Use `-nostreams` for a share where you would rather not have it on disk:
Windows then leaves the streams out, and macOS writes `._` files instead.

## The library

```go
import (
	"strings"

	"github.com/tobychui/smbsrv"
	"github.com/tobychui/smbsrv/localfs"
)

func main() {
	share, err := localfs.New(localfs.Config{Name: "public", Path: "/srv/public"})
	if err != nil {
		panic(err)
	}
	hash := smbsrv.NTHash("secret")
	backend, err := localfs.NewBackend(localfs.Options{
		Lookup: func(name string) (string, []byte, bool) {
			if strings.EqualFold(name, "alice") {
				return "alice", hash, true
			}
			return "", nil, false
		},
		Shares: func(username string) []smbsrv.Share { return []smbsrv.Share{share} },
	})
	if err != nil {
		panic(err)
	}
	server, err := smbsrv.New(smbsrv.Config{Address: ":445", ServerName: "NAS", Backend: backend})
	if err != nil {
		panic(err)
	}
	if err := server.Start(); err != nil {
		panic(err)
	}
	defer server.Close()
	select {}
}
```

### Packages

| Package | What it is |
| --- | --- |
| `smbsrv` | The server: `Config`, `New`, `Start`, `Close`, `Clients`, `DropUser`, and the `Backend` interfaces. |
| `smbsrv/localfs` | Shares over folders of the local disk (`New`), and a `Backend` from two functions (`NewBackend`). Keeps everything inside the folder: links leading off it are hidden and refused, and on Windows names the disk would store differently (`a:b`, `CON`, a trailing dot) are refused. |
| `smbsrv/wsd` | WS-Discovery and LLMNR responder that lists a server in the Windows Network view. |
| `smbsrv/cmd/smbsrv` | The command above, a complete example of using the library. |

The protocol itself is in `internal/` (`wire`, `crypt`, `auth`, `rpc`,
`state`, `osfile`) and is not part of the API.

### Writing a Backend

To serve something other than local folders (an object store, a database, the
drives of your own application), implement `smbsrv.Backend`:

```go
type Backend interface {
	LookupHash(username string) (name string, ntHash []byte, ok bool)
	Login(username string) (UserView, error)
	Allow(remote net.IP) bool
	AuthLog(username, remote string, ok bool) time.Duration
}
```

`Login` returns a `UserView` whose `Shares` are `smbsrv.Share` values: a small
file system interface (`Stat`, `ReadDir`, `Open`, `Mkdir`, `Remove`, `Rename`,
`SetModTime`, `Usage`, ...) plus `CanRead` / `CanWrite`, which the server asks
on every operation. Paths are relative to the share root, use forward slashes,
and `""` is the root. A Share can implement more to unlock more of the
protocol:

| Interface | Gives clients |
| --- | --- |
| `StreamShare` | Named streams. Stream paths arrive as `path + smbsrv.StreamSeparator + name`. |
| `SnapshotShare` | Previous Versions in Windows Explorer. |
| `PollableShare` | Change notifications for changes made around the server, by listing watched folders every few seconds. |
| `InternalShare` | A folder name the share keeps for itself, hidden from listings and refused to writes. |
| `PendingFile` (on a `File`) | The size of a file whose writes reach storage later, such as a staged upload. |

`Config.Logger` takes a `*slog.Logger` for logins, refused connections and
protocol trouble; it defaults to `slog.Default()`.

## Tests

```bash
go test ./...
```

The tests drive the server with its own raw client and with
[go-smb2](https://github.com/hirochachacha/go-smb2), an independent client.
On Linux and macOS they also run `smbclient`, `rpcclient` and Wireshark's
dissector against it when those are installed.

## License

MIT, see [LICENSE](LICENSE).
