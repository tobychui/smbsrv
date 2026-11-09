//go:build !unix && !windows

package main

import "os"

var stopSignals = []os.Signal{os.Interrupt}
