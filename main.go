package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/pufferffish/wireproxy"
	"github.com/sourcegraph/conc"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %v <wireguard-config-file> <destination-addr-with-port>\n", os.Args[0])
		return
	}

	configFilePath := os.Args[1]
	targetAddress := os.Args[2]

	config, err := wireproxy.ParseConfig(configFilePath)
	if err != nil {
		log.Fatalf("Could not parse config file: %v\n", err)
	}

	wireguard, err := wireproxy.StartWireguard(config.Device, device.LogLevelError)
	if err != nil {
		log.Fatalf("Could not start wireguard: %v\n", err)
	}

	stdioTcpForward(wireguard.Tnet, targetAddress)
}

func mustIoCopy(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	_, err := io.Copy(to, from)
	if err != nil {
		log.Fatalf("Cannot forward traffic: %v\n", err)
	}
}

func stdioTcpForward(vnet *netstack.Net, destination string) {
	conn, err := vnet.DialTCP(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(destination)))
	defer func(conn io.Closer) {
		_ = conn.Close()
	}(conn)

	if err != nil {
		log.Fatalf("TCP Client Tunnel establishment error: %v\n", err)
	}

	wg := conc.NewWaitGroup()
	wg.Go(func() {
		mustIoCopy(os.Stdin, conn)
	})
	wg.Go(func() {
		mustIoCopy(conn, os.Stdout)
	})
	wg.Wait()
}
