package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
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
	ConfigKey    uint32 = 0
	ETHPAll      uint16 = 0x0003
	Window              = 30 * time.Second
	MaxCount     uint64 = 10
	FilterHandle uint32 = 0x00010001
)

func CreateTCHookAndShowDropLog(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	pods, err := PodsByLabel(ctx)
	if err != nil {
		return fmt.Errorf("find pods by label: %w", err)
	}

	if len(pods) == 0 {
		return fmt.Errorf("no pods found for selector %q in namespace %q", LabelSelector, Namespace)
	}

	targetPod := pods[0]

	hostVethIface, err := hostVethFromPod(ctx, targetPod)
	if err != nil {
		return fmt.Errorf("find host veth interface %s from pod %s: %w", hostVethIface.Name, targetPod.Name, err)
	}

	var agent Agent
	agent.watchSet = make(map[uint32]struct{})
	agent.ifIndex = uint32(hostVethIface.Index)
	agent.ifName = hostVethIface.Name
	agent.tcHandle = FilterHandle

	if err := loadCount_conn_and_dropObjects(&agent.objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer agent.objs.Close()

	tcClient, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("open tc netlink: %w", err)
	}
	agent.tcClient = tcClient
	defer agent.tcClient.Close()

	if err := agent.applyRateLimitConfig(Window, MaxCount); err != nil {
		return fmt.Errorf("apply rate limit config: %w", err)
	}
	log.Printf("put rate limit config into eBPF map")

	podIPs := PodIPsFromInfos(pods)
	if len(podIPs) == 0 {
		return fmt.Errorf("pods found but no pod IPs for selector %q in namespace %q", LabelSelector, Namespace)
	}

	log.Printf("pods of %s in namespace %s are: %v", LabelSelector, Namespace, podIPs)

	if err := agent.setWatchIPs(podIPs); err != nil {
		return fmt.Errorf("set watch IPs: %w", err)
	}

	if err := ensureClsact(agent.tcClient, agent.ifIndex); err != nil {
		return fmt.Errorf("ensure clsact on %s: %w", agent.ifName, err)
	}

	if err := attachBPFProgram(
		agent.tcClient,
		agent.ifIndex,
		agent.objs.CountSynAndDrop.FD(),
		"count_syn_and_drop",
		agent.tcHandle,
	); err != nil {
		return fmt.Errorf("attach tc bpf to %s: %w", agent.ifName, err)
	}

	defer func() {
		if err := deleteClsact(agent.tcClient, agent.ifIndex); err != nil {
			log.Printf("delete clsact failed: if=%s ifindex=%d: %v",
				agent.ifName, agent.ifIndex, err)
		}
	}()

	log.Printf("rate-limit config applied: window=%s max_count=%d", Window, MaxCount)
	log.Printf("watching pod selector=%q pod_ips=%v on host veth=%s ifindex=%d",
		LabelSelector, podIPs, agent.ifName, agent.ifIndex)
	log.Printf("attached tc egress program: if=%s ifindex=%d",
		agent.ifName, agent.ifIndex)

	reader, err := ringbuf.NewReader(agent.objs.DropEvents)
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

func runDropEventLoop(ctx context.Context, reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				if ctx.Err() != nil {
					return nil
				}
				return nil
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

func PodIPsFromInfos(pods []PodInfo) []string {
	ips := make([]string, 0, len(pods))
	for _, pod := range pods {
		if pod.PodIP == "" {
			continue
		}
		ips = append(ips, pod.PodIP)
	}
	return ips
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

	if err := tcnl.Qdisc().Add(&qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact: %w", err)
	}
	return nil
}

func deleteClsact(tcnl *tc.Tc, ifindex uint32) error {
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

	if err := tcnl.Qdisc().Delete(&qdisc); err != nil &&
		!errors.Is(err, unix.ENOENT) &&
		!errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("delete clsact: %w", err)
	}
	return nil
}

func attachBPFProgram(tcnl *tc.Tc, ifindex uint32, progFD int, progName string, handle uint32) error {
	fd := uint32(progFD)
	flags := uint32(0x1) // direct-action

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  handle,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
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
			Handle:  handle,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    core.FilterInfo(0, unix.ETH_P_ALL),
		},
	}
	return tcnl.Filter().Delete(&filter)
}
