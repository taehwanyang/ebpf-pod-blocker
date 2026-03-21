//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

struct ip_pair_key {
    __u32 target_ip;
    __u32 src_ip;
};

// rate limit config from user space
struct rl_config {
    __u64 window_ns;
    __u64 max_count;
    __u32 pad; 
};

struct rl_state {
    struct bpf_spin_lock lock;
    __u64 window_start_ns;
    __u32 count;
    __u32 pad;
};

struct drop_event {
    __u64 ts_ns;
    __u32 target_ip;
    __u32 src_ip;
    __u32 count;
    __u32 max_count;
};

// user space 설정 rate limit config
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_config);
} config_map SEC(".maps");

// user space가 관리하는 watch 대상 dst_ip 목록
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} watch_dst_ips SEC(".maps");

/*
* (target_ip, src_ip)별 rate limit 상태 저장
* key = {target_ip, src_ip}
* value = rl_state
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_pair_key);
    __type(value, struct rl_state);
} target_src_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MiB
} drop_events SEC(".maps");

static __always_inline int parse_ipv4_tcp(
    struct __sk_buff *skb,
    struct iphdr **iph,
    struct tcphdr **tcph) 
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    if (ip->version != 4)
        return -1;

    if (ip->protocol != IPPROTO_TCP)
        return -1;

    __u32 ihl_len = (__u32)ip->ihl * 4;
    if (ihl_len < sizeof(*ip))
        return -1;

    if ((void *)ip + ihl_len > data_end)
        return -1;

    struct tcphdr *tcp = (void *)ip + ihl_len;
    if ((void *)(tcp + 1) > data_end)
        return -1;

    *iph = ip;
    *tcph = tcp;
    return 0;
}

static __always_inline void emit_drop_event(
    __u64 now_ns,
    __u32 target_ip,
    __u32 src_ip,
    __u32 count,
    __u32 max_count)
{
    struct drop_event *evt;
    evt = bpf_ringbuf_reserve(&drop_events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    evt->ts_ns = now_ns;
    evt->target_ip = target_ip;
    evt->src_ip = src_ip;
    evt->count = count;
    evt->max_count = max_count;

    bpf_ringbuf_submit(evt, 0);
}

SEC("tc")
int count_syn_and_drop(struct __sk_buff *skb)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u64 now_ns;
    __u32 cfg_key = 0;
    __u8 *enabled;
    struct rl_config *cfg;
    struct ip_pair_key pair_key;
    struct rl_state *state;

    if (parse_ipv4_tcp(skb, &ip, &tcp) < 0) {
        return TC_ACT_OK;
    }

    if (!tcp->syn || tcp->ack) {
        return TC_ACT_OK;
    }

    bpf_printk("syn seen daddr=%x saddr=%x\n", bpf_ntohl(ip->daddr), bpf_ntohl(ip->saddr));

    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u32 src_ip = bpf_ntohl(ip->saddr);
    enabled = bpf_map_lookup_elem(&watch_dst_ips, &dst_ip);
    if (!enabled) {
        bpf_printk("watch miss daddr=%x\n", ip->daddr);
        return TC_ACT_OK;
    }

    pair_key.target_ip = dst_ip;
    pair_key.src_ip = src_ip;

    bpf_printk("watch hit daddr=%x\n", dst_ip);

    cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg) {
        return TC_ACT_OK;
    }

    if (cfg->window_ns == 0 || cfg->max_count == 0) {
        return TC_ACT_OK;
    }

    state = bpf_map_lookup_elem(&target_src_states, &pair_key);
    if (!state) {
        struct rl_state init_state = {};
        init_state.window_start_ns = bpf_ktime_get_ns();
        init_state.count = 1;

        bpf_map_update_elem(&target_src_states, &pair_key, &init_state, BPF_ANY);
        return TC_ACT_OK;
    }

    now_ns = bpf_ktime_get_ns();
    
    bpf_spin_lock(&state->lock);
    
    if (now_ns - state->window_start_ns >= cfg->window_ns) {
        state->window_start_ns =now_ns;
        state->count = 1;
        bpf_spin_unlock(&state->lock);
        return TC_ACT_OK;
    }

    state->count += 1;

    if (state->count > cfg->max_count) {
        __u32 current_count = state->count;
        __u32 max_count = cfg->max_count;
        __u32 target_ip = pair_key.target_ip;
        __u32 src_ip = pair_key.src_ip;

        bpf_spin_unlock(&state->lock);

        bpf_printk("drop target=%x src=%x count=%u\n",
               target_ip, src_ip, current_count);

        emit_drop_event(now_ns, target_ip, src_ip, current_count, max_count);
        return TC_ACT_SHOT;
    }

    bpf_spin_unlock(&state->lock);

    bpf_printk("pass target=%x src=%x count=%u\n",
               pair_key.target_ip, pair_key.src_ip, state->count);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";