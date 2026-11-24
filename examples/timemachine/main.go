// Command timemachine is the smallest Time Machine server smbsrv makes: one
// user, and the folder ./backup offered to Macs as a backup disk.
//
//	go run ./examples/timemachine -user alice -pw secret
//
// On the Mac, connect to smb://HOST/TimeMachine once in Finder (Go > Connect
// to Server) as that user, then pick the share in System Settings > General >
// Time Machine > Add Backup Disk. Keep the server on port 445: Macs store the
// Time Machine password without a port, and a backup to any other port fails
// to sign in. Ports below 1024 need root on Linux (see the README).
//
// This example does not announce itself over Bonjour, which is why the share
// is connected once by hand. cmd/smbsrv is the full server, with more users,
// more shares and settings that change while it runs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/tobychui/smbsrv"
	"github.com/tobychui/smbsrv/localfs"
)

// shareName is what Macs open, as smb://HOST/TimeMachine.
const shareName = "TimeMachine"

// maxLimitGB keeps the size limit in bytes far from overflowing.
const maxLimitGB = 1 << 30

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, nil); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "timemachine:", err)
		}
		os.Exit(1)
	}
}

// run serves until ctx ends. ready, when set, is told the address the server
// listens on, for tests.
func run(ctx context.Context, args []string, out io.Writer, ready func(net.Addr)) error {
	fs := flag.NewFlagSet("timemachine", flag.ContinueOnError)
	addr := fs.String("addr", ":445", "listen `address`; Time Machine needs port 445")
	dir := fs.String("dir", "./backup", "`folder` the backups are kept in, created when missing")
	user := fs.String("user", "", "`name` Macs sign in with")
	password := fs.String("pw", "", "`password` of that user (default: the SMBSRV_PASSWORD variable)")
	limitGB := fs.Uint64("max", 0, "most the backups may take, in `GB`; 0 is the whole disk")
	name := fs.String("name", "", "server `name` Macs show (default SMBSRV)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *password == "" {
		*password = os.Getenv("SMBSRV_PASSWORD")
	}
	if *user == "" || *password == "" {
		return errors.New("a user and a password are needed: -user NAME -pw PASSWORD")
	}
	if *limitGB > maxLimitGB {
		return fmt.Errorf("-max must be at most %d GB", uint64(maxLimitGB))
	}

	//The backups hold everything on the Mac, so only this account may read them
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	folder, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	share, err := localfs.New(localfs.Config{
		Name:               shareName,
		Path:               folder,
		Comment:            "Time Machine backups",
		TimeMachine:        true,
		TimeMachineMaxSize: *limitGB << 30,
	})
	if err != nil {
		return err
	}

	hash := smbsrv.NTHash(*password)
	backend, err := localfs.NewBackend(localfs.Options{
		Lookup: func(username string) (string, []byte, bool) {
			if strings.EqualFold(username, *user) {
				return *user, hash, true
			}
			return "", nil, false
		},
		Shares: func(string) []smbsrv.Share { return []smbsrv.Share{share} },
	})
	if err != nil {
		return err
	}
	server, err := smbsrv.New(smbsrv.Config{
		Address:    *addr,
		ServerName: *name,
		Backend:    backend,
		//Macs only back up to a server that answers their Apple extensions
		Apple: true,
	})
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		server.Close()
		return err
	}
	defer server.Close()

	host, err := os.Hostname()
	if err != nil {
		host = "HOST"
	}
	if tcp, ok := server.Addr().(*net.TCPAddr); ok && tcp.Port != 445 {
		host = net.JoinHostPort(host, fmt.Sprint(tcp.Port))
	}
	limit := "the whole disk"
	if *limitGB > 0 {
		limit = fmt.Sprintf("up to %d GB", *limitGB)
	}
	fmt.Fprintf(out, "Time Machine backups go to %s (%s).\n", folder, limit)
	fmt.Fprintf(out, "On the Mac: Finder > Go > Connect to Server, open smb://%s/%s and sign in as %s,\n", host, shareName, *user)
	fmt.Fprintln(out, "then choose it in System Settings > General > Time Machine > Add Backup Disk.")
	fmt.Fprintln(out, "Press Ctrl+C to stop.")
	if ready != nil {
		ready(server.Addr())
	}

	<-ctx.Done()
	return nil
}
