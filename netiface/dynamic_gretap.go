package netiface

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
)

type BPFfilter struct {
	base          string
	excludedIPs   *[]string
	excludedPorts *[]string
}

func (f BPFfilter) String() string {
	str := f.base
	fmt.Printf("excludedIPs: %+v\n", *(f.excludedIPs))
	fmt.Printf("excludedPorts: %+v\n", *(f.excludedPorts))

	for _, port := range *(f.excludedPorts) {
		str += " and port not " + port
	}

	return str
}

func (f *BPFfilter) addExcludedIP(ip string) {
	str := strings.Trim(ip, " ")
	*(f.excludedIPs) = append(*(f.excludedIPs), str)
}

func (f *BPFfilter) addExcludedPort(port string) {
	str := strings.Trim(port, " ")
	*(f.excludedPorts) = append(*(f.excludedPorts), str)
}

type gretapTunManager struct {
	localIP     string
	remoteIP    *[]string
	remotePort  *[]string
	brLink      netlink.Link
	listenIface *net.Interface
	nextTunNum  int
	filter      BPFfilter
}

func NewGretapTunManager(listenIfaceName string, brName string, BPFbase string) (*gretapTunManager, error) {
	m := &gretapTunManager{nextTunNum: 0, remoteIP: &[]string{}, remotePort: &[]string{}}

	f := BPFfilter{base: BPFbase, excludedIPs: m.remoteIP, excludedPorts: m.remotePort}
	m.filter = f

	if brLink, err := netlink.LinkByName(brName); err != nil {
		return nil, err
	} else {
		m.brLink = brLink
	}

	fmt.Printf("iface: %+v\n", listenIfaceName)
	if iface, err := net.InterfaceByName(listenIfaceName); err != nil {
		return nil, err
	} else {
		m.listenIface = iface
		if addrs, err := iface.Addrs(); err != nil {
			return nil, err
		} else {
			str := addrs[0].String()
			m.localIP = strings.Split(str, "/")[0]
		}
	}

	return m, nil
}

func (m *gretapTunManager) newTun(ip string, sport uint16, dport uint16) {
	attr := netlink.NewLinkAttrs()
	m.nextTunNum += 1
	attr.Name = "GRETAP" + fmt.Sprintf("%d", m.nextTunNum)

	gretap := &netlink.Gretap{
		Local: net.ParseIP(m.localIP), Remote: net.ParseIP(ip), LinkAttrs: attr,
		EncapSport: sport, EncapDport: dport,
		EncapType: netlink.FOU_ENCAP_DIRECT,
	}

	if err := netlink.LinkAdd(gretap); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}

	if err := netlink.LinkSetMaster(gretap, m.brLink); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}

	if err := netlink.LinkSetUp(gretap); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v", err.Error()))
	}
}

func (m *gretapTunManager) listen(pkt gopacket.Packet) {
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

	udpLayer := pkt.Layers()[2].(*layers.UDP)
	fmt.Printf("\tUDP Header:\n")
	fmt.Printf("\t Src: %d -> Dst: %d\n", udpLayer.SrcPort, udpLayer.DstPort)

	udpPayload := pkt.Layers()[3].(*gopacket.Payload)
	greLayer := layers.GRE{}
	if err := greLayer.DecodeFromBytes(
		udpPayload.LayerContents(), gopacket.NilDecodeFeedback); err != nil {
		fmt.Print(fmt.Errorf("\tGRE DecodeFromBytes: %+v", err.Error()))
	}
	fmt.Printf("\tGRE Header:\n")
	fmt.Printf("\t  Protocol: %s\n", greLayer.Protocol.LayerType())

	inEthLayer := layers.Ethernet{}
	if err := inEthLayer.DecodeFromBytes(
		greLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
		fmt.Print(fmt.Errorf("\tGRE DecodeFromBytes: %+v", err.Error()))
	}
	fmt.Printf("\tInner Ethernet Header:\n")
	fmt.Printf("\t  MAC address: %s -> %s\n", inEthLayer.SrcMAC, inEthLayer.DstMAC)
	fmt.Printf("\t  Type: %s\n", inEthLayer.EthernetType)

	inIPLayer := layers.IPv4{}
	if err := inIPLayer.DecodeFromBytes(
		inEthLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
		fmt.Print(fmt.Errorf("\tGRE DecodeFromBytes: %+v", err.Error()))
	}
	fmt.Printf("\tInner IP Header:\n")
	fmt.Printf("\t  Src: %s -> Dst: %s\n", inIPLayer.SrcIP, inIPLayer.DstIP)

	m.filter.addExcludedIP(outIPLayer.SrcIP.String())
	m.filter.addExcludedPort(udpLayer.SrcPort.String())

	m.newTun(outIPLayer.SrcIP.String(), uint16(udpLayer.DstPort), uint16(udpLayer.SrcPort))
}

func (m *gretapTunManager) Start() {
	print("Starting GRE tunnel manager...\n")
	Capture(m.listenIface.Index, m.filter, m.listen)
}
