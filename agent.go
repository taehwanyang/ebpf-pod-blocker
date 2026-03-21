package main

import (
	"fmt"
	"time"

	"github.com/florianl/go-tc"
)

type Agent struct {
	objs     connection_counterObjects
	tcClient *tc.Tc
	watchSet map[uint32]struct{}
	ifIndex  uint32
	ifName   string
	tcHandle uint32
}

func (a *Agent) applyRateLimitConfig(window time.Duration, maxCount uint64) error {
	val := connection_counterRlConfig{
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
