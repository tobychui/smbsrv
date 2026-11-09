// Command smbsrv is a single binary SMB file server built on the smbsrv
// library. Accounts and shares are kept in smbsrv.json beside the binary:
//
//	smbsrv -a alice -pw "very secure password"   add a user
//	smbsrv -f /srv/photos                        share a folder
//	smbsrv                                       start the server
//
// Run smbsrv -h for every option.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/tobychui/smbsrv"
	"github.com/tobychui/smbsrv/localfs"
	"github.com/tobychui/smbsrv/wsd"
)

const usageHead = `smbsrv - a single binary SMB 2/3 file server

Usage:
  smbsrv                            start the server
  smbsrv -a NAME [-pw PASSWORD]     add a user, or change their password
                                    (asked for when -pw is left out)
  smbsrv -d NAME                    delete a user
  smbsrv -f FOLDER [-n NAME] [-ro] [-u USER,USER] [-nostreams]
                                    share a folder; again to change its settings
  smbsrv -rm NAME                   stop sharing a folder
  smbsrv -l                         list users and shares

Settings live in smbsrv.json beside the binary (-c for another file). Users
and shares can be changed while the server runs.

Options:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// serveOptions are the per run overrides of the file's server settings.
type serveOptions struct {
	address    string
	serverName string
	capture    string
	announce   *bool
	encrypt    *bool
	ready      func(net.Addr) //For tests: called once the server listens
}

func run(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("smbsrv", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageHead)
		fs.PrintDefaults()
	}
	configPath := fs.String("c", "", "configuration `file` (default smbsrv.json beside the binary)")
	addUser := fs.String("a", "", "add a user, or change the password of one, by `name`")
	password := fs.String("pw", "", "`password` for -a")
	delUser := fs.String("d", "", "delete the user of this `name`")
	folder := fs.String("f", "", "share this `folder`")
	shareName := fs.String("n", "", "share `name` for -f (default: the folder's name)")
	readOnly := fs.Bool("ro", false, "make the -f share read only")
	shareUsers := fs.String("u", "", "comma separated `users` who may open the -f share (default: every user)")
	noStreams := fs.Bool("nostreams", false, "do not keep named streams for the -f share")
	removeShare := fs.String("rm", "", "stop sharing the share of this `name`")
	fs.Bool("l", false, "list users and shares")
	address := fs.String("addr", "", "listen `address` for this run, such as :1445 (default from the file, :445)")
	serverName := fs.String("name", "", "server `name` for this run (default from the file)")
	announce := fs.Bool("announce", false, "show the server in the Windows Network view (WS-Discovery)")
	encrypt := fs.Bool("encrypt", false, "refuse clients that cannot encrypt (SMB 2.1, and 3.x with encryption off)")
	capture := fs.String("capture", "", "write a pcap and a trace log of every connection to this `folder`, for debugging")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "smbsrv: unexpected argument %q (quote values that hold spaces)\n", fs.Arg(0))
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if set["pw"] && !set["a"] {
		fmt.Fprintln(stderr, "smbsrv: -pw goes with -a NAME")
		return 2
	}
	for _, name := range []string{"n", "ro", "u", "nostreams"} {
		if set[name] && !set["f"] {
			fmt.Fprintf(stderr, "smbsrv: -%s goes with -f FOLDER\n", name)
			return 2
		}
	}

	path := *configPath
	if path == "" {
		path = DefaultConfigPath()
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintln(stderr, "smbsrv:", err)
		return 1
	}

	managing := set["a"] || set["d"] || set["f"] || set["rm"] || set["l"]
	if managing {
		changed := false
		if set["a"] {
			pw := *password
			if !set["pw"] {
				if pw, err = readPassword(*addUser, stdin, stderr); err != nil {
					fmt.Fprintln(stderr, "smbsrv:", err)
					return 1
				}
			}
			created, err := cfg.SetUser(*addUser, pw)
			if err != nil {
				fmt.Fprintln(stderr, "smbsrv:", err)
				return 1
			}
			if created {
				fmt.Fprintf(stdout, "Added user %s\n", *addUser)
			} else {
				fmt.Fprintf(stdout, "Changed the password of %s\n", cfg.FindUser(*addUser).Name)
			}
			changed = true
		}
		if set["d"] {
			if err := cfg.DeleteUser(*delUser); err != nil {
				fmt.Fprintln(stderr, "smbsrv:", err)
				return 1
			}
			fmt.Fprintf(stdout, "Deleted user %s\n", *delUser)
			changed = true
		}
		if set["f"] {
			sc := ShareConfig{Name: *shareName, Path: *folder, ReadOnly: *readOnly, NoStreams: *noStreams}
			if *shareUsers != "" {
				sc.Users = strings.Split(*shareUsers, ",")
			}
			added, updated, err := cfg.AddShare(sc)
			if err != nil {
				fmt.Fprintln(stderr, "smbsrv:", err)
				return 1
			}
			if updated {
				fmt.Fprintf(stdout, "Updated share %s -> %s\n", added.Name, added.Path)
			} else {
				fmt.Fprintf(stdout, "Shared %s as %s\n", added.Path, added.Name)
			}
			for _, u := range added.Users {
				if cfg.FindUser(u) == nil {
					fmt.Fprintf(stderr, "Note: there is no user %q yet\n", u)
				}
			}
			changed = true
		}
		if set["rm"] {
			if err := cfg.RemoveShare(*removeShare); err != nil {
				fmt.Fprintln(stderr, "smbsrv:", err)
				return 1
			}
			fmt.Fprintf(stdout, "Stopped sharing %s\n", *removeShare)
			changed = true
		}
		if changed {
			if err := cfg.Save(path); err != nil {
				fmt.Fprintln(stderr, "smbsrv: could not save the settings:", err)
				return 1
			}
			fmt.Fprintf(stdout, "Saved %s\n", path)
		}
		if set["l"] {
			printList(stdout, path, cfg)
		}
		return 0
	}

	opt := serveOptions{address: *address, serverName: *serverName, capture: *capture}
	if set["announce"] {
		opt.announce = announce
	}
	if set["encrypt"] {
		opt.encrypt = encrypt
	}
	if err := serve(ctx, path, cfg, opt, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "smbsrv:", err)
		return 1
	}
	return 0
}

// serve runs the server until ctx ends.
func serve(ctx context.Context, path string, cfg *Config, opt serveOptions, stdout, stderr io.Writer) error {
	if len(cfg.Users) == 0 {
		return errors.New("there are no users yet; add one with: smbsrv -a NAME")
	}
	if len(cfg.Shares) == 0 {
		return errors.New("nothing is shared yet; share a folder with: smbsrv -f FOLDER")
	}
	address := firstNonEmpty(opt.address, cfg.Address)
	name := firstNonEmpty(opt.serverName, cfg.ServerName)
	announce := cfg.Announce
	if opt.announce != nil {
		announce = *opt.announce
	}
	encrypt := cfg.RequireEncryption
	if opt.encrypt != nil {
		encrypt = *opt.encrypt
	}
	guid, err := cfg.guid()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	st := newStore(path, cfg, logger)
	backend, err := localfs.NewBackend(localfs.Options{
		Lookup:               st.lookup,
		Shares:               st.shares,
		AllowPublicAddresses: cfg.AllowPublicAddresses,
	})
	if err != nil {
		return err
	}
	server, err := smbsrv.New(smbsrv.Config{
		Address:           address,
		ServerName:        name,
		Workgroup:         cfg.Workgroup,
		GUID:              guid,
		Backend:           backend,
		Logger:            logger,
		CaptureDir:        opt.capture,
		RequireEncryption: encrypt,
	})
	if err != nil {
		return err
	}
	//A removed account, or one with a new password, is logged out at once
	st.onReload = func(old, cur *Config) {
		for _, u := range changedUsers(old, cur) {
			if n := server.DropUser(u); n > 0 {
				logger.Info("Logged out " + u + ": the account changed")
			}
		}
	}
	if err := server.Start(); err != nil {
		server.Close()
		if hint := bindHint(address, err); hint != "" {
			return fmt.Errorf("cannot listen on %s: %w\n%s", address, err, hint)
		}
		return fmt.Errorf("cannot listen on %s: %w", address, err)
	}
	defer server.Close()

	printShares(stdout, name, st.current())
	if opt.ready != nil {
		opt.ready(server.Addr())
	}

	if announce {
		if _, port, _ := net.SplitHostPort(address); port != "445" {
			logger.Info("Not announcing: the Windows Network view only opens servers on port 445")
		} else {
			responder, err := wsd.Start(wsd.Config{
				Name:      name,
				Workgroup: cfg.Workgroup,
				UUID:      cfg.uuid(),
				Logger:    logger,
			})
			if err != nil {
				logger.Warn("Could not announce the server, it still works by name or address", "err", err)
			} else {
				defer responder.Close()
			}
		}
	}

	<-ctx.Done()
	logger.Info("Stopping")
	return nil
}

// bindHint explains the usual reasons a listen fails.
func bindHint(address string, err error) string {
	_, port, _ := net.SplitHostPort(address)
	msg := err.Error()
	switch {
	case runtime.GOOS == "windows" && port == "445":
		return `Windows keeps port 445 for its own file sharing. Listen on another port with
-addr :1445; Windows 11 24H2 and newer can open it with
  net use \\HOST\share /TCPPORT:1445
and macOS with smb://HOST:1445/share. Or run smbsrv on another computer.`
	case errors.Is(err, os.ErrPermission) || strings.Contains(msg, "permission denied"):
		exe, _ := os.Executable()
		return "Ports below 1024 need more rights. Run smbsrv as root, or allow this binary\nonce with: sudo setcap cap_net_bind_service=+ep " + exe
	case strings.Contains(msg, "in use") || strings.Contains(msg, "Only one usage"):
		return "Another program, such as Samba, uses this port. Stop it, or listen on\nanother port with -addr."
	}
	return ""
}

func printShares(w io.Writer, name string, cfg *Config) {
	fmt.Fprintf(w, "smbsrv is serving %d share(s) to %d user(s):\n", len(cfg.Shares), len(cfg.Users))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, s := range cfg.Shares {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", `\\`+name+`\`+s.Name, s.Path, accessText(s))
	}
	tw.Flush()
	fmt.Fprintln(w, "Press Ctrl+C to stop.")
}

func printList(w io.Writer, path string, cfg *Config) {
	fmt.Fprintf(w, "Settings: %s\n", path)
	fmt.Fprintf(w, "Server:   %s (%s), listening on %s\n", cfg.ServerName, cfg.Workgroup, cfg.Address)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nUsers:")
	if len(cfg.Users) == 0 {
		fmt.Fprintln(tw, "  (none, add one with -a NAME)")
	}
	users := append([]User{}, cfg.Users...)
	sort.Slice(users, func(i, j int) bool { return strings.ToLower(users[i].Name) < strings.ToLower(users[j].Name) })
	for _, u := range users {
		fmt.Fprintf(tw, "  %s\tpassword set %s\n", u.Name, u.Changed.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(tw, "\nShares:")
	if len(cfg.Shares) == 0 {
		fmt.Fprintln(tw, "  (none, share a folder with -f FOLDER)")
	}
	for _, s := range cfg.Shares {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", s.Name, s.Path, accessText(s))
	}
	tw.Flush()
}

func accessText(s ShareConfig) string {
	mode := "read and write"
	if s.ReadOnly {
		mode = "read only"
	}
	who := "every user"
	if len(s.Users) > 0 {
		who = strings.Join(s.Users, ", ")
	}
	return mode + ", " + who
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
