/*
 * tracing filter example
 * if attached to /sys/kernel/debug/tracing/events/net/netif_receive_skb
 * it will print events for loobpack device only
 */
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <trace/bpf_trace.h>

void filter(struct bpf_context *ctx)
{
	char devname[4] = "lo";
	struct net_device *dev;
	struct sk_buff *skb = 0;

	skb = (struct sk_buff *)ctx->regs.si;
	dev = bpf_load_pointer(&skb->dev);
	if (bpf_memcmp(dev->name, devname, 2) == 0) {
		char fmt[] = "skb %p dev %p \n";
		bpf_trace_printk(fmt, sizeof(fmt), (long)skb, (long)dev, 0);
	}
}
