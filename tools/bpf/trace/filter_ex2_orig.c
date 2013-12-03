/*
 * tracing filter that counts number of events per device
 * if attached to /sys/kernel/debug/tracing/events/net/netif_receive_skb
 * it will count number of received packets for different devices
 */
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <trace/bpf_trace.h>

struct dev_key {
	void *dev;
};

struct dev_leaf {
	uint64_t packet_cnt;
};

void filter(struct bpf_context *ctx)
{
	struct net_device *dev;
	struct sk_buff *skb = 0;
	struct dev_leaf *leaf;
	struct dev_key key = {};

	skb = (struct sk_buff *)ctx->regs.si;
	dev = bpf_load_pointer(&skb->dev);

	key.dev = dev;
	leaf = bpf_table_lookup(ctx, 0, &key);
	if (leaf) {
		__sync_fetch_and_add(&leaf->packet_cnt, 1);
		if (leaf->packet_cnt % 10000 == 0) {
			char fmt[] = "dev %p  pkt_cnt %d\n";
			bpf_trace_printk(fmt, sizeof(fmt), (long)dev,
					 leaf->packet_cnt, 0);
		}
	} else {
		struct dev_leaf new_leaf = {};
		bpf_table_update(ctx, 0, &key, &new_leaf);
	}
}

struct bpf_table filter_tables[] = {
	{BPF_TABLE_HASH, sizeof(struct dev_key), sizeof(struct dev_leaf), 4096, 0}
};

