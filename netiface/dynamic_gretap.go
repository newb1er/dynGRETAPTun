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
	proto       string
	localIP     *string
	excludedIPs *[]string
}

func (f BPFfilter) String() string {
	str := "proto " + f.proto + " and dst host " + *f.localIP
	for _, ip := range *f.excludedIPs {
		str += " and not host " + ip
	}

	return str
}

func (f *BPFfilter) addExcludedIP(ip string) {
	str := strings.Trim(ip, " ")
	*(f.excludedIPs) = append(*(f.excludedIPs), str)
}

type gretapTunManager struct {
	localIP     string
	remoteIP    *[]string
	brLink      netlink.Link
	listenIface *net.Interface
	nextTunNum  int
	filter      BPFfilter
}

func NewGretapTunManager(listenIfaceName string, brName string) (*gretapTunManager, error) {
	strArr := []string{}
	m := &gretapTunManager{nextTunNum: 0, remoteIP: &strArr}

	f := BPFfilter{proto: "GRE", localIP: &m.localIP, excludedIPs: m.remoteIP}
	m.filter = f

	if brLink, err := netlink.LinkByName(brName); err != nil {
		return nil, err
	} else {
		m.brLink = brLink
	}

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

func (m *gretapTunManager) newTun(ip string) {
	attr := netlink.NewLinkAttrs()
	m.nextTunNum += 1
	attr.Name = "GRETAP" + fmt.Sprintf("%d", m.nextTunNum)

	gretap := &netlink.Gretap{Local: net.ParseIP(m.localIP), Remote: net.ParseIP(ip), LinkAttrs: attr}

	if err := netlink.LinkAdd(gretap); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v\n", err.Error()))
	}

	if err := netlink.LinkSetMaster(gretap, m.brLink); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v\n", err.Error()))
	}

	if err := netlink.LinkSetUp(gretap); err != nil {
		fmt.Print(fmt.Errorf("newTun: %+v\n", err.Error()))
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

	greLayer := pkt.Layers()[2].(*layers.GRE)
	fmt.Printf("\tGRE Header:\n")
	fmt.Printf("\t  Protocol: %s\n", greLayer.Protocol.LayerType())

	inEthLayer := pkt.Layers()[3].(*layers.Ethernet)
	fmt.Printf("\tInner Ethernet Header:\n")
	fmt.Printf("\t  MAC address: %s -> %s\n", inEthLayer.SrcMAC, inEthLayer.DstMAC)
	fmt.Printf("\t  Type: %s\n", inEthLayer.EthernetType)

	m.filter.addExcludedIP(outIPLayer.SrcIP.String())

	m.newTun(outIPLayer.SrcIP.String())
}

func (m *gretapTunManager) Start() {
	Capture(m.listenIface.Index, m.filter, m.listen)
}
