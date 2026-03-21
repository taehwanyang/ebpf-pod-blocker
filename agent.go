package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/florianl/go-tc"
)

type Agent struct {
	objs     count_conn_and_dropObjects
	tcClient *tc.Tc
	watchSet map[uint32]struct{}
	ifIndex  uint32
	ifName   string
	tcHandle uint32
}

func (a *Agent) applyRateLimitConfig(window time.Duration, maxCount uint64) error {
	val := count_conn_and_dropRlConfig{
		WindowNs: uint64(window.Nanoseconds()),
		MaxCount: maxCount,
	}

	if err := a.objs.ConfigMap.Put(ConfigKey, val); err != nil {
		return fmt.Errorf("update config_map: %w", err)
	}

	return nil
}

func (a *Agent) setWatchIPs(ipStrs []string) error {
	newSet := make(map[uint32]struct{}, len(ipStrs))

	for _, s := range ipStrs {
		ipU32, err := ipToU32(s)
		if err != nil {
			return fmt.Errorf("invalid pod ip %q: %w", s, err)
		}
		log.Printf("watch ip=%s key=0x%08x", s, ipU32)
		newSet[ipU32] = struct{}{}
	}

	for ip := range newSet {
		enabled := uint8(1)
		if err := a.objs.WatchDstIps.Put(ip, enabled); err != nil {
			return fmt.Errorf("add watch dst ip %s: %w", u32ToIP(ip), err)
		}
	}

	a.watchSet = newSet
	return nil
}

func ipToU32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not IPv4: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func u32ToIP(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}
