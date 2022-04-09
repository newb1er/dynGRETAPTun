package main

import (
	"flag"
	"fmt"
	"os"

	"gretool/netiface"
)

const (
	showIface string = "showif"
)

func init() {
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: gretool [ showif ]\n")
	flag.PrintDefaults()
}

func main() {
	flag.Parse()

	args := flag.Args()

	if len(args) < 1 {
		usage()
		return
	}

	switch args[0] {
	case showIface:
		netiface.PrintInterfaces()
	default:
		usage()
		return
	}
}
