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
	ConfigKey     uint32 = 0
	ETHPAll       uint16 = 0x0003
	Window               = time.Minute
	MaxCount      uint64 = 100
	LocalNodeName        = "lima-ubuntu-ebpf"
)

func WatchPodTrafficAndBlockPodOnDetection(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var agent Agent
	agent.watchSet = make(map[uint32]struct{})

	if err := loadConnection_counterObjects(&agent.objs, nil); err != nil {
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
		return err
	}

	pods := PodsByLabel()
	if len(pods) == 0 {
		return fmt.Errorf("no pods found for selector %q in namespace %q", LabelSelector, Namespace)
	}

	podIPs := PodIPsFromInfos(pods)
	if err := agent.setWatchIPs(podIPs); err != nil {
		return err
	}

	vethInfos, err := FindHostVethsForPods(ctx, pods, LocalNodeName)
	if err != nil {
		return fmt.Errorf("find host-side veths: %w", err)
	}
	if len(vethInfos) == 0 {
		return fmt.Errorf("no host-side veth found for selector %q on node %q", LabelSelector, LocalNodeName)
	}

	for i, info := range vethInfos {
		iface, err := net.InterfaceByName(info.VethName)
		if err != nil {
			return fmt.Errorf("find interface %q for pod %s/%s: %w", info.VethName, info.Namespace, info.PodName, err)
		}

		ifindex := uint32(iface.Index)

		if err := ensureClsact(agent.tcClient, ifindex); err != nil {
			return fmt.Errorf("ensure clsact on %s: %w", info.VethName, err)
		}

		filterHandle := uint32(i + 1)

		if err := attachBPFProgram(
			agent.tcClient,
			ifindex,
			agent.objs.CountSynAndDrop.FD(),
			"count_syn_and_drop",
			filterHandle,
		); err != nil {
			return fmt.Errorf("attach tc bpf to %s: %w", info.VethName, err)
		}

		agent.attachments = append(agent.attachments, AttachedInterface{
			IfIndex:      ifindex,
			FilterHandle: filterHandle,
			IfName:       info.VethName,
			PodName:      info.PodName,
			PodIP:        info.PodIP,
		})
	}

	defer func() {
		for _, att := range agent.attachments {
			if err := deleteBPFProgram(agent.tcClient, att.IfIndex, att.FilterHandle); err != nil {
				log.Printf("delete tc filter failed: if=%s ifindex=%d: %v", att.IfName, att.IfIndex, err)
			}
		}
	}()

	log.Printf("rate-limit config applied: window=%s max_count=%d", Window, MaxCount)
	log.Printf("watching pod selector=%q pod_ips=%v", LabelSelector, podIPs)

	for _, att := range agent.attachments {
		log.Printf("attached tc ingress program: pod=%s podIP=%s hostVeth=%s ifindex=%d",
			att.PodName, att.PodIP, att.IfName, att.IfIndex)
	}

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
			Info:    core.FilterInfo(0, ETHPAll),
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
			Info:    core.FilterInfo(0, ETHPAll),
		},
	}

	return tcnl.Filter().Delete(&filter)
}
