package main

import (
	"bufio"
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

func interactive() {
	var inIface string
	var inFilter string

	netiface.PrintInterfaces()
	fmt.Printf("Select interface: ")
	fmt.Scanf("%s", &inIface)
	fmt.Printf("Selected interface: %s\n", inIface)

	in := bufio.NewReader(os.Stdin)
	fmt.Printf("BPF filter expression: \n")
	inFilter, _ = in.ReadString('\n')

	fmt.Printf("BPF filter expression: %s\n", inFilter)

	manager, err := netiface.NewGretapTunManager(inIface, "BR", inFilter)
	if err != nil {
		fmt.Print(fmt.Errorf("main: %+v", err.Error()))
	}

	manager.Start()
}

func main() {
	flag.Parse()

	args := flag.Args()

	if len(args) < 1 {
		interactive()
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

		var inFilter string
		var err error
		in := bufio.NewReader(os.Stdin)
		fmt.Printf("BPF filter expression: \n")
		if inFilter, err = in.ReadString('\n'); err != nil {
			fmt.Print(fmt.Errorf("main: %+v", err.Error()))
		}

		fmt.Printf("BPF filter expression: %s\n", inFilter)

		manager, err := netiface.NewGretapTunManager(ifFlag, "BR", inFilter)
		if err != nil {
			fmt.Print(fmt.Errorf("main: %+v", err.Error()))
		}

		manager.Start()
	default:
		usage()
		return
	}
}
