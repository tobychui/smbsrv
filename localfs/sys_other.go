//go:build !windows

package localfs

// checkComponent accepts every name: apart from the slash, which never
// reaches a component, and NUL, which the server uses as the stream separator,
// these systems store any byte as it is.
func checkComponent(name string) error { return nil }
