package netiface

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type Filter interface {
	String() string
}

func PrintInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("PrintInterfaces: %+v\n", err.Error()))
	}

	for _, iface := range ifaces {
		fmt.Printf("%d: %s\n", iface.Index, iface.Name)
		fmt.Printf("Hardware Addr: %s\n", iface.HardwareAddr)

		fmt.Printf("Ip Addrs:\n")
		if addrs, err := iface.Addrs(); err != nil {
			fmt.Print(fmt.Errorf("PrintInterfaces: %+v\n", err.Error()))
		} else {
			for _, addr := range addrs {
				fmt.Printf("\t%s %s\n", addr.Network(), addr.String())
			}
		}
	}
}

func Capture(idx int, filter Filter, callback func(gopacket.Packet)) {
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		fmt.Print(fmt.Errorf("Capture: %+v\n", err.Error()))
		return
	}

	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Print(fmt.Errorf("Capture: %+v\n", err.Error()))
		return
	}

	handle.SetBPFFilter(filter.String())
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		callback(packet)
		handle.SetBPFFilter(filter.String())
	}
}

func LinkByType(t string) ([]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	var res []netlink.Link

	for _, link := range links {
		if link.Type() == t {
			res = append(res, link)
		}
	}

	return res, nil
}
