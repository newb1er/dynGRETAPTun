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
	ifFlag string
)

func init() {
	flag.Usage = usage
	flag.StringVar(&ifFlag, "i", "", "interface name")
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
		if ifFlag == "" {
			usage()
			return
		}
		manager, err := netiface.NewGretapTunManager(ifFlag, "BR")
		if err != nil {
			fmt.Print(fmt.Errorf("main: %+v", err.Error()))
		}

		manager.Start()
	default:
		usage()
		return
	}
}
