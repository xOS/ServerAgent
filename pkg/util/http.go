package util

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

var DNSServersV4 = []string{"8.8.4.4:53", "223.5.5.5:53", "94.140.14.140:53", "119.29.29.29:53"}
var DNSServersV6 = []string{"[2001:4860:4860::8844]:53", "[2400:3200::1]:53", "[2a10:50c0::1:ff]:53", "[2402:4e00::]:53"}
var DNSServersAll = append(DNSServersV4, DNSServersV6...)

func NewSingleStackHTTPClient(httpTimeout, dialTimeout, keepAliveTimeout time.Duration, ipv6 bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAliveTimeout,
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			ip, err := resolveIP(ctx, addr, ipv6)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, ip)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
	}
}

func resolveIP(ctx context.Context, addr string, ipv6 bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	dnsServers := DNSServersV6
	network := "ip6"
	if !ipv6 {
		dnsServers = DNSServersV4
		network = "ip4"
	}

	res, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		for i := 0; i < len(dnsServers); i++ {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * 10,
					}
					return d.DialContext(ctx, "udp", dnsServers[i])
				},
			}
			res, err = r.LookupIP(ctx, network, host)
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		return "", err
	}

	if len(res) == 0 {
		if ipv6 {
			return "", errors.New("the AAAA record not resolved")
		}
		return "", errors.New("the A record not resolved")
	}

	return net.JoinHostPort(res[0].String(), port), nil
}
