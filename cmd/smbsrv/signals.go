//go:build unix || windows

package main

import (
	"os"
	"syscall"
)

// stopSignals end the server. On Windows, Go raises SIGTERM when the console
// closes or the computer shuts down.
var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
