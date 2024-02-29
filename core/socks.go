package core

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/things-go/go-socks5"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("%s -> DIRECT", addr)

	return goDial(ctx, network, addr)
}

func ServeSocks5(ipStack *stack.Stack, selfIp []byte, bindAddr string) {
	var dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Check if is IPv6
		if strings.Count(addr, ":") > 1 {
			return dialDirect(ctx, network, addr)
		}

		parts := strings.Split(addr, ":")

		// in normal situation, addr must be a pure valid IP
		// because we use `ZJUDnsResolve` to resolve domain name before call `Dial`
		host := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, errors.New("Invalid port in address: " + addr)
		}

		var target *net.IPAddr

		if pureIp := net.ParseIP(host); pureIp != nil {
			// host is pure IP format, e.g.: "10.10.10.10"
			target = &net.IPAddr{IP: pureIp}
		} else {
			// illegal situation
			log.Printf("Illegal situation, host is not pure IP format: %s", host)
			return dialDirect(ctx, network, addr)
		}

		// proxy
		addrTarget := tcpip.FullAddress{
			NIC:  defaultNIC,
			Port: uint16(port),
			Addr: tcpip.Address(target.IP),
		}

		bind := tcpip.FullAddress{
			NIC:  defaultNIC,
			Addr: tcpip.Address(selfIp),
		}

		if network == "tcp" {
			log.Printf("[TCP]: %s -> PROXY", addr)
			return gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
		} else if network == "udp" {
			log.Printf("[UDP]: %s -> PROXY", addr)
			return gonet.DialUDP(ipStack, &bind, &addrTarget, header.IPv4ProtocolNumber)
		} else {
			log.Printf("Proxy only support TCP/UDP. Connection to %s will use direct connection.", addr)
			return dialDirect(ctx, network, addr)
		}
	}

	server := socks5.NewServer(
		socks5.WithDial(dialer),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "", log.LstdFlags))),
	)

	log.Printf(">>>SOCKS5 SERVER listening on<<<: " + bindAddr)

	if err := server.ListenAndServe("tcp", bindAddr); err != nil {
		panic("socks listen failed: " + err.Error())
	}
}
