# dynGRETAPTun
A simple dynamic GRETAP tunnel program. It capture GRE packet and setup GRETAP interface on linux bridge by itself.

## Diagram
![Untitled Diagram(1)](https://user-images.githubusercontent.com/32424677/162781684-a683bfd8-2eb9-4f74-aa5a-c257eb39ee1a.jpg)

## Environment Setup

```bash
ip link add BR type bridge
ip link set <LAN iface name> master BR
go build
```

## Command

`showif` : show interface
```bash
gretool showif
```

`capture` : capture GRE packet on designated interface

```bash
gretool -i <iface name> capture
# -i : interface
```
once the program capture GRE packet, it will create a GRETAP interface with master set to "BR".
