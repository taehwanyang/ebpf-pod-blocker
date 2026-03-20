package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

type dropEvent struct {
	TsNs     uint64
	TargetIp uint32
	SrcIp    uint32
	Count    uint32
	MaxCount uint32
}

const (
	ConfigKey uint32 = 0
	IfaceName        = "eth0"
	Window           = time.Minute
	MaxCount  uint64 = 100
)

type Runtime struct {
	objs         connection_counterObjects
	tcClient     *tc.Tc
	ifaceIndex   uint32
	filterHandle uint32
	watchSet     map[uint32]struct{}
}

func WatchPodTrafficAndBlockPodOnDetection(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var rt Runtime
	rt.watchSet = make(map[uint32]struct{})

	if err := loadConnection_counterObjects(&rt.objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer rt.objs.Close()

	iface, err := net.InterfaceByName(IfaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", IfaceName, err)
	}
	rt.ifaceIndex = uint32(iface.Index)

	tcClient, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("open tc netlink: %w", err)
	}
	rt.tcClient = tcClient
	defer rt.tcClient.Close()

	if err := ensureClsact(rt.tcClient, rt.ifaceIndex); err != nil {
		return fmt.Errorf("ensure clsact: %w", err)
	}

	rt.filterHandle = 1
	if err := attachBPFProgram(rt.tcClient, rt.ifaceIndex, rt.objs.CountSynAndDrop.FD(), "count_syn_and_drop", rt.filterHandle); err != nil {
		return fmt.Errorf("attach tc bpf: %w", err)
	}
	defer func() {
		if err := deleteBPFProgram(rt.tcClient, rt.ifaceIndex, rt.filterHandle); err != nil {
			log.Printf("delete tc filter failed: %v", err)
		}
	}()

	if err := rt.applyRateLimitConfig(Window, MaxCount); err != nil {
		return err
	}

	podIPs := PodIpsByLabel()
	if len(podIPs) == 0 {
		log.Printf("warning: no pod IPs found for selector %q", LabelSelector)
	} else {
		if err := rt.setWatchIPs(podIPs); err != nil {
			return err
		}
	}

	log.Printf("tc program attached on iface=%s", IfaceName)
	log.Printf("rate-limit config applied: window=%s max_count=%d", Window, MaxCount)
	log.Printf("watching pod selector=%q pod_ips=%v", LabelSelector, podIPs)

	reader, err := ringbuf.NewReader(rt.objs.DropEvents)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	return runDropEventLoop(ctx, reader)
}

func (rt *Runtime) applyRateLimitConfig(window time.Duration, maxCount uint64) error {
	val := connection_counterRlConfig{
		WindowNs: uint64(window.Nanoseconds()),
		MaxCount: maxCount,
	}

	if err := rt.objs.ConfigMap.Put(ConfigKey, val); err != nil {
		return fmt.Errorf("update config_map: %w", err)
	}

	return nil
}

func (rt *Runtime) setWatchIPs(ipStrs []string) error {
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
		if err := rt.objs.WatchDstIps.Put(ip, enabled); err != nil {
			return fmt.Errorf("add watch dst ip %s: %w", u32ToIP(ip), err)
		}
	}

	rt.watchSet = newSet
	return nil
}

func runDropEventLoop(ctx context.Context, reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		var evt dropEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("decode drop event failed: %v", err)
			continue
		}

		log.Printf(
			"[DROP] recv_time=%s src=%s dst=%s count=%d limit=%d kernel_ts_ns=%d",
			time.Now().Format(time.RFC3339),
			u32ToIP(evt.SrcIp),
			u32ToIP(evt.TargetIp),
			evt.Count,
			evt.MaxCount,
			evt.TsNs,
		)
	}
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

func ensureClsact(tcnl *tc.Tc, ifindex uint32) error {
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	err := tcnl.Qdisc().Add(&qdisc)
	if err != nil {
		return nil
	}
	return nil
}

func attachBPFProgram(tcnl *tc.Tc, ifindex uint32, progFD int, progName string, handle uint32) error {
	fd := uint32(progFD)
	flags := uint32(0x1) // TCA_BPF_FLAG_ACT_DIRECT

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Parent:  tc.HandleMinIngress,
			Handle:  handle,
			Info:    core.FilterInfo(0, unix.ETH_P_ALL),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Name:  &progName,
				Flags: &flags,
			},
		},
	}

	return tcnl.Filter().Add(&filter)
}

func deleteBPFProgram(tcnl *tc.Tc, ifindex uint32, handle uint32) error {
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Parent:  tc.HandleMinIngress,
			Handle:  handle,
			Info:    core.FilterInfo(0, unix.ETH_P_ALL),
		},
	}

	return tcnl.Filter().Delete(&filter)
}
