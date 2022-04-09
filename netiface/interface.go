package netiface

import (
	"fmt"
	"net"
)

func PrintInterfaces() {
	ifaces, err := net.Interfaces()

	if err != nil {
		fmt.Print(fmt.Errorf("PrintInterfaces: %+v", err.Error()))
		return
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()

		if err != nil {
			fmt.Print(fmt.Errorf("PrintInterfaces: %+v", err.Error()))
		}

		fmt.Printf("%d: %s\n", iface.Index, iface.Name)
		fmt.Printf("Hardware Addr: %s\n", iface.HardwareAddr)

		fmt.Printf("Ip Addrs:\n")
		for _, addr := range addrs {
			fmt.Printf("\t%s %s\n", addr.Network(), addr.String())
		}
	}
}
