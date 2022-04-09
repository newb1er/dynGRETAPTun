package main

import (
	"flag"
	"fmt"
	"os"

	"gretool/netiface"
)

const (
	showIface string = "showif"
	capture   string = "capture"
)

var (
	idxFlag int
)

func init() {
	flag.Usage = usage
	flag.IntVar(&idxFlag, "i", -1, "interface index")
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: gretool [ showif | capture ]\n")
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
	case capture:
		if idxFlag == -1 {
			usage()
			return
		}
		netiface.Capture(idxFlag)
	default:
		usage()
		return
	}
}
