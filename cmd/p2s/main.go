// Command p2s is the php2shell-audit scanner and threat hunter.
package main

import (
	"os"

	"github.com/darkLabz001/php2shell-audit/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
