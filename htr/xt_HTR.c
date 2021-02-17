#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/checksum.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <asm/errno.h>
#include <linux/netfilter/x_tables.h>
#include "xt_HTR.h"

MODULE_AUTHOR("Maksym Hryshanov <maksym.hryshanov@gmail.com>");
MODULE_DESCRIPTION("Xtables: HTTP redirect target");
MODULE_LICENSE("GPL");

//HTTP/1.1 301 Moved Permanently
//Location: http://redirect_url
//Connection: close

static int send_v4_tcp(struct net *net, __be32 src, __be32 dst, __be16 sport, __be16 dport, u32 seq, u32 ack)
{
    struct sk_buff *skb = NULL;
    struct iphdr *iph;
    struct tcphdr *th;
    int err;
    char *data;

    if (!skb) {
        skb = alloc_skb(LL_MAX_HEADER + sizeof(*iph) + sizeof(*th), GFP_ATOMIC);
        if (!skb) {
            pr_err("Cannot allocate memory for skb\n");
            return -ENOMEM;
        }
        skb_reserve(skb, LL_MAX_HEADER);
    }

    skb_reset_network_header(skb);
    iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
    th  = (struct tcphdr *)skb_put(skb, sizeof(*th));
    iph->version    = 4;
    iph->ihl        = sizeof(*iph) / 4;
    iph->tos        = 0;
    iph->id         = 0;
    iph->frag_off   = htons(IP_DF);
    iph->ttl        = net->ipv4.sysctl_ip_default_ttl;
    iph->protocol   = IPPROTO_TCP;
    iph->saddr      = src;
    iph->daddr      = dst;

    th->source      = sport;
    th->dest        = dport;
    th->psh         = 1;
    th->ack         = 1;
    th->seq         = htonl(seq);
    th->ack_seq     = htonl(seq);
    th->window      = 515;
    th->urg_ptr     = 0;

    skb->protocol   = htons(ETH_P_IP);

    data = (char *)th + (th->doff * 4);

    pr_debug("ip_local_out: %pI4n:%hu -> %pI4n:%hu (seq=%u, "
         "ack_seq=%u)\n", &src, ntohs(th->source),
         &dst, ntohs(th->dest), ntohl(th->seq), ntohl(th->ack_seq));

//    err = __ip_local_out(net, skb->sk, skb);

//    if (err > 0) {
//        err = net_xmit_errno(err);
//        pr_debug("ip_local_out: return with %d\n", err);
//    }

    if (skb)
        kfree_skb(skb);

    return err;
}

static unsigned int
htr_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *iph;
    struct tcphdr *th ;
    const struct ipt_htr_info *info = par->targinfo;
    struct net *net = par->net;

    int ret,err;

    iph = ip_hdr(skb);
    th  = tcp_hdr(skb);

    ret = XT_CONTINUE;

    err = send_v4_tcp(net, iph->saddr, iph->daddr, th->source, th->dest, th->seq, th->ack_seq);
//    if (skb) {
//        kfree_skb(skb);
//        ret = NF_STOLEN;
//    }

    return ret;
}

static int htr_tg_check(const struct xt_tgchk_param *par)
{
    const struct xt_htr_info *info = par->targinfo;

    return 0;
}

static struct xt_target htr_tg_reg[] __read_mostly = {
    {
        .name       = "HTR",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .target     = htr_tg,
        .targetsize = sizeof(struct xt_htr_info),
        .checkentry = htr_tg_check,
        .me         = THIS_MODULE,
    },
};

static int __init htr_tg_init(void)
{
    return xt_register_targets(htr_tg_reg, ARRAY_SIZE(htr_tg_reg));
}

static void __exit htr_tg_exit(void)
{
    xt_unregister_targets(htr_tg_reg, ARRAY_SIZE(htr_tg_reg));
}

module_init(htr_tg_init);
module_exit(htr_tg_exit);
MODULE_ALIAS("ipt_HTR");
MODULE_ALIAS("ipt_HTTPREDIRECT");
