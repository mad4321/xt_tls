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

#define XT_HTR_DEBUG

MODULE_AUTHOR("Maksym Hryshanov <maksym.hryshanov@gmail.com>");
MODULE_DESCRIPTION("Xtables: HTTP redirect target");
MODULE_LICENSE("GPL");

static char PAYLOAD[] = "HTTP/1.1 301 Moved permanently\r\nLocation: %s\r\nConnection: close\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n";

static unsigned int
htr_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    const struct xt_htr_info *info = par->targinfo;

    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);

    struct net *net = xt_net(par);

    struct sk_buff *nskb = NULL;
    struct iphdr *niph;
    struct tcphdr *nth;

    char *data;
    size_t plen  = skb->len - skb_transport_offset(skb) - th->doff * 4;
    size_t nplen = sizeof(PAYLOAD)-2 + strlen(info->host) - 1;

    int ret,err;

    if (!nskb) {
        nskb = alloc_skb(sizeof(*niph) + sizeof(*nth) + MAX_TCP_HEADER + nplen + 1, GFP_ATOMIC);
        if (!nskb) {
            pr_err("Cannot allocate memory for skb\n");
            return -ENOMEM;
        }
        skb_reserve(nskb, MAX_TCP_HEADER);
    }

    skb_reset_network_header(nskb);
    skb_reset_transport_header(nskb);
    niph = (struct iphdr *)skb_put(nskb, sizeof(*niph));
    niph->version     = 4;
    niph->ihl         = sizeof(*niph) / 4;
    niph->tos         = 0;
    niph->id          = 0;
    niph->frag_off    = htons(IP_DF);
    niph->ttl         = net->ipv4.sysctl_ip_default_ttl;
    niph->protocol    = IPPROTO_TCP;
    niph->saddr       = iph->daddr;
    niph->daddr       = iph->saddr;

    skb_reset_transport_header(nskb);
    nth  = (struct tcphdr *)skb_put(nskb, sizeof(*nth));
    nth->source      = th->dest;
    nth->dest        = th->source;
    nth->seq         = th->ack_seq;
    nth->ack_seq     = htonl(ntohl(th->seq) + plen);
    tcp_flag_word(nth) = TCP_FLAG_FIN | TCP_FLAG_ACK;
    nth->doff        = sizeof(*nth) / 4;
//    nth->window      = th->window;
    nth->window      = htons(512);
    nth->check       = 0;
    nth->urg_ptr     = 0;

    nskb->protocol    = htons(ETH_P_IP);
    nskb->len         = nplen + sizeof(*niph) + sizeof(*nth);
    niph->tot_len     = htons(nskb->len);

    data = (char *)nth + (nth->doff * 4);
    sprintf(data, PAYLOAD, info->host);

    nth->check = ~tcp_v4_check(sizeof(*nth)+nplen, niph->saddr, niph->daddr, 0);
    nskb->ip_summed   = CHECKSUM_PARTIAL;
    nskb->csum_start  = (unsigned char *)nth - nskb->head;
    nskb->csum_offset = offsetof(struct tcphdr, check);

    skb_dst_set_noref(nskb, skb_dst(skb));

#ifdef XT_HTR_DEBUG
    printk("ip_local_out: %pI4n:%hu -> %pI4n:%hu (seq=%u, "
         "ack_seq=%u) iph_len=%u, th_len=%u, p_len=%u, total_len=%u\n", &niph->saddr, ntohs(nth->source),
         &niph->daddr, ntohs(nth->dest), ntohl(nth->seq), ntohl(nth->ack_seq), sizeof(*niph), sizeof(*nth), nplen, nskb->len);

    printk("ip_header[]: %20ph\n", niph);
    printk("tcp_header[]: %20ph\n", nth);

    printk("payload[]: %s\n", data);
#endif

//    ip_send_check(niph);
    err = ip_local_out(net, nskb->sk, nskb);

//    if (nskb) {
//        kfree_skb(nskb);
//    }


    ret = NF_DROP;
//    ret = XT_CONTINUE;

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
