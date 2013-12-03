Tracing filter examples

filter_ex1: tracing filter example that prints events for loobpack device only

$ cat filter_ex1.bpf > /sys/kernel/debug/tracing/events/net/netif_receive_skb/filter
$ echo 1 > /sys/kernel/debug/tracing/events/net/netif_receive_skb/enable
$ ping -c1 localhost
$ cat /sys/kernel/debug/tracing/trace_pip
            ping-5913  [003] ..s2  3779.285726: __netif_receive_skb_core: skb ffff880808e3a300 dev ffff88080bbf8000
            ping-5913  [003] ..s2  3779.285744: __netif_receive_skb_core: skb ffff880808e3a900 dev ffff88080bbf8000

To pre-check correctness of the filter do:
$ trace_filter_check filter_ex1.bpf
(final filter check always happens in kernel)

