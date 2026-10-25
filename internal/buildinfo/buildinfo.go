// Package buildinfo carries the values injected at link time by the Makefile.
package buildinfo

var (
	// Version is the release version, for example "0.1.0".
	Version = "dev"
	// Commit is the short git commit the binary was built from.
	Commit = "unknown"
	// Date is the UTC build timestamp.
	Date = "unknown"
)
