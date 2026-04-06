// SPDX-License-Identifier: GPL-2.0
/*
 * Ralink ESW DSA tagger
 */
#include <linux/dsa/8021q.h>

#include "tag.h"
#include "tag_8021q.h"

#define RALINK_CPU_TXQ_BRIDGED_BASE     0      /* TX0/TX1 */
#define RALINK_CPU_TXQ_STANDALONE_BASE  BIT(1) /* TX2/TX3 */

#define RALINK_PORT_MASK                0x0007

/*
 * Map Linux queue_mapping onto the two CPU DMA rings. Bridged and
 * standalone traffic use separate queue pairs.
 */
static struct sk_buff *ralink_tag_xmit(struct sk_buff *skb,
                       struct net_device *netdev)
{
    struct dsa_port *dp = dsa_user_to_port(netdev);
    struct net_device *br = dsa_port_bridge_dev_get(dp);
    u16 qmap, tx_vid;

    qmap = skb_get_queue_mapping(skb);
    qmap = ((qmap >> 1) & 1) |
           (br ? RALINK_CPU_TXQ_BRIDGED_BASE
           : RALINK_CPU_TXQ_STANDALONE_BASE);
    skb_set_queue_mapping(skb, qmap);

    if (br && br_vlan_enabled(br))
        return skb;

    tx_vid = dsa_tag_8021q_standalone_vid(dp);

    return dsa_8021q_xmit(skb, netdev, ETH_P_8021Q, tx_vid);
}

/*
 * The outer TPID carries low-bit source-port information. Use it when
 * available, then let tag_8021q decode the VLAN context.
 */
static struct sk_buff *ralink_tag_rcv(struct sk_buff *skb,
                      struct net_device *netdev)
{
    int src_port, switch_id = -1, vbid = -1, vid = -1;
    struct vlan_ethhdr *hdr;
    u16 tpid;

    if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
        return NULL;

    hdr = vlan_eth_hdr(skb);
    tpid = ntohs(hdr->h_vlan_proto);

    if (unlikely((tpid & ~RALINK_PORT_MASK) != ETH_P_8021Q))
        return NULL;

    src_port = tpid & RALINK_PORT_MASK;

    /* Port 0 is ambiguous with plain 0x8100.
     * Do not trust it and let tag_8021q decoding handle it.
     */
    if (!src_port)
        src_port = -1;

    dsa_8021q_rcv(skb, &src_port, &switch_id, &vbid, &vid);

    skb->dev = dsa_tag_8021q_find_user(netdev, src_port, switch_id,
                       vid, vbid);
    if (!skb->dev) {
        dev_warn_ratelimited(&netdev->dev, "Couldn't decode source port\n");
        return NULL;
    }

    dsa_default_offload_fwd_mark(skb);

    return skb;
}

static const struct dsa_device_ops ralink_tag_ops = {
        .name           = "ralink",
        .proto          = DSA_TAG_PROTO_RALINK,
        .xmit           = ralink_tag_xmit,
        .rcv            = ralink_tag_rcv,
        .needed_headroom = VLAN_HLEN,
};

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ralink ESW DSA tagger");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_RALINK, "ralink");

module_dsa_tag_driver(ralink_tag_ops);