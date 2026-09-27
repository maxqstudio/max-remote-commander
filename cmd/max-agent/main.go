package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("max-agent", version)
		return
	}
	fmt.Fprintln(os.Stderr, "max-agent: no server configured; use --version for build verification")
	os.Exit(2)
}
