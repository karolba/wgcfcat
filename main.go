package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/kirsle/configdir"
	"github.com/pufferffish/wireproxy"
	"github.com/sourcegraph/conc"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	flAcceptWarpEula = flag.Bool("accept-warp-tos", false, "Accept the Cloudflare WARP Terms Of Service (reqired)")
	flConfigDir      = flag.String("config-dir", configdir.LocalConfig("ssh-over-warp"), "Configuration directory")
	flHost           = flag.String("host", "", "Host to connect to over cloudflare WARP")
	flPort           = flag.Uint("port", 0, "Port to connect to over cloudflare WARP")
	// TODO: udp -u
	// TODO: use pflags for short and long flags
)

func wgcfAccountConfigPath() string {
	return filepath.Join(*flConfigDir, "wgcf-account.toml")
}

func mustBase64WireguardKeyToHex(key string) string {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatalf("could not convert wireguard base64 key to hex, invalid base64 string: %s\n", key)
	}
	if len(decoded) != 32 {
		log.Fatalf("could not convert wireguard key to hex, key should be 32 bytes: %s\n", key)
	}
	return hex.EncodeToString(decoded)
}

func mustResolveIPPAndPort(addr string) *string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("Could not split '%s' into a host and port: %v\n", addr, err)
	}

	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		log.Fatalf("Cannot resolve '%s': %v\n", host, err)
	}
	joined := net.JoinHostPort(ip.String(), port)
	return &joined
}

func main() {
	flag.Parse()
	if !*flAcceptWarpEula || *flHost == "" || *flPort == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if err := os.MkdirAll(*flConfigDir, os.ModePerm); err != nil {
		log.Fatalf("Could not create the config directory '%s': %v\n", *flConfigDir, err)
	}

	warpAccount := &Account{}
	if !warpAccount.tryToLoadFromConfig(wgcfAccountConfigPath()) {
		if err := warpAccount.register(); err != nil {
			log.Fatalf("Could not register a warp account: %v\n", err)
		}
		if err := warpAccount.saveToConfig(wgcfAccountConfigPath()); err != nil {
			log.Fatalf("Could not save warp account details to the config file: %v\n", err)
		}
	}

	wireguard, err := wireproxy.StartWireguard(&wireproxy.DeviceConfig{
		MTU:       1280,
		SecretKey: mustBase64WireguardKeyToHex(warpAccount.PrivateKey),
		Endpoint: []netip.Addr{
			netip.MustParseAddr(warpAccount.ThisDevice.Config.Interface.Addresses.V4),
			netip.MustParseAddr(warpAccount.ThisDevice.Config.Interface.Addresses.V6),
		},
		DNS: []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("1.0.0.1"),
			netip.MustParseAddr("2606:4700:4700::1111"),
			netip.MustParseAddr("2606:4700:4700::1001"),
		},
		Peers: []wireproxy.PeerConfig{
			wireproxy.PeerConfig{
				PublicKey:    mustBase64WireguardKeyToHex(warpAccount.ThisDevice.Config.Peers[0].PublicKey),
				Endpoint:     mustResolveIPPAndPort(warpAccount.ThisDevice.Config.Peers[0].Endpoint.Host),
				PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
				KeepAlive:    0, // todo - expose this as a flag
				AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
			},
		},
	}, device.LogLevelError)
	if err != nil {
		log.Fatalf("Could not start a wireguard client: %v\n", err)
	}

	_, hostIp, err := wireguard.Resolve(context.Background(), *flHost)
	if err != nil {
		log.Fatalf("Could not resolve '%s' (over wireguard): %v\n", *flHost, err)
	}

	hostIpAddr, ok := netip.AddrFromSlice(hostIp)
	if !ok {
		log.Fatalf("Could not convert '%v' to netip.Addr\n", hostIp)
	}

	stdioTcpForward(wireguard.Tnet, hostIpAddr, uint16(*flPort))
}

func mustIoCopy(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	_, err := io.Copy(to, from)
	if err != nil {
		log.Fatalf("Cannot forward traffic: %v\n", err)
	}
}

func stdioTcpForward(vnet *netstack.Net, host netip.Addr, port uint16) {
	conn, err := vnet.DialTCPAddrPort(netip.AddrPortFrom(host, port))
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
