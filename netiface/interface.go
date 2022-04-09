package netiface

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

var (
	scnr = scanner{initialized: false, filter: "proto gre ", nextTunNum: 1}
)

type scanner struct {
	initialized bool
	ifaces      []net.Interface
	filter      string
	nextTunNum  int
}

func (s *scanner) init() (err error) {
	if s.initialized != false {
		return nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	s.ifaces = ifaces
	return nil
}

func (s *scanner) newTun(src string, dst string) {
	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(dst)
	attr := netlink.NewLinkAttrs()
	attr.Name = "GRETAP" + fmt.Sprintf("%d", s.nextTunNum)
	s.nextTunNum = s.nextTunNum + 1

	gretap := netlink.Gretap{Local: srcIP, Remote: dstIP, LinkAttrs: attr}

	if err := netlink.LinkAdd(&gretap); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}

	brLink, err := netlink.LinkByName("BR")
	if err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}

	greLink, err := netlink.LinkByName(attr.Name)
	if err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}

	if err := netlink.LinkSetMaster(greLink, brLink); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}

	if err := netlink.LinkSetUp(greLink); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}
}

func (s *scanner) parsePacket(pkt gopacket.Packet) {
	fmt.Printf("new packet captured: \n")
	fmt.Printf("\t\t")
	for idx, b := range pkt.Data() {
		if (idx+1)%16 == 0 {
			fmt.Printf("%02x\n\t\t", b)
		} else {
			fmt.Printf("%02x ", b)
		}
	}
	fmt.Printf("\n")

	outEthLayer := pkt.LinkLayer().(*layers.Ethernet)
	fmt.Printf("\tOuter Ethernet Header:\n")
	fmt.Printf("\t  MAC address: %s -> %s\n", outEthLayer.SrcMAC, outEthLayer.DstMAC)
	fmt.Printf("\t  Type: %s\n", outEthLayer.EthernetType)

	outIPLayer := pkt.Layers()[1].(*layers.IPv4)
	fmt.Printf("\tOuter IP Header:\n")
	fmt.Printf("\t  Src: %s -> Dst: %s\n", outIPLayer.SrcIP, outIPLayer.DstIP)

	greLayer := pkt.Layers()[2].(*layers.GRE)
	fmt.Printf("\tGRE Header:\n")
	fmt.Printf("\t  Protocol: %s\n", greLayer.Protocol)

	inEthLayer := pkt.Layers()[3].(*layers.Ethernet)
	fmt.Printf("\tInner Ethernet Header:\n")
	fmt.Printf("\t  MAC address: %s -> %s\n", inEthLayer.SrcMAC, inEthLayer.DstMAC)
	fmt.Printf("\t  Type: %s\n", inEthLayer.EthernetType)

	s.filter = s.filter + "and not host " + outIPLayer.SrcIP.String()

	s.newTun(outIPLayer.DstIP.String(), outIPLayer.SrcIP.String())
}

func (s *scanner) scan(idx int) {
	if handle, err := pcap.OpenLive(s.ifaces[idx].Name, 1600, true, pcap.BlockForever); err != nil {
		fmt.Print(fmt.Errorf("scan: %+v\n", err.Error()))
		return
	} else {
		handle.SetBPFFilter(s.filter)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			s.parsePacket(packet)
			handle.SetBPFFilter(s.filter)
		}
	}
}

func Capture(idx int) {
	err := scnr.init()

	if err != nil {
		fmt.Print(fmt.Errorf("capture: %+v", err.Error()))
		return
	}

	fmt.Println("capturing: ", scnr.ifaces[idx-1].Name)
	scnr.scan(idx - 1)
}

func PrintInterfaces() {
	err := scnr.init()

	if err != nil {
		fmt.Print(fmt.Errorf("PrintInterfaces: %+v", err.Error()))
		return
	}

	for line, iface := range scnr.ifaces {
		addrs, err := iface.Addrs()

		if err != nil {
			fmt.Print(fmt.Errorf("PrintInterfaces: %+v", err.Error()))
		}

		fmt.Printf("%d: %s\n", line+1, iface.Name)
		fmt.Printf("Hardware Addr: %s\n", iface.HardwareAddr)

		fmt.Printf("Ip Addrs:\n")
		for _, addr := range addrs {
			fmt.Printf("\t%s %s\n", addr.Network(), addr.String())
		}
	}
}
