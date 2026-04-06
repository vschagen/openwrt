// SPDX-License-Identifier: GPL-2.0
/*
 * Ralink Frame Engine driver
 * Copyright (c) 2026 Richard van Schagen <richard@routerwrt.org>
 */

#include <generated/utsrelease.h>
#include <linux/clk.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/string.h>
#include <linux/u64_stats_sync.h>

#include <net/dsa.h>
#include <net/page_pool/helpers.h>

#include "ralink_fe.h"

static inline u32 ralink_fe_rx_irq_bit(int q)
{
	return BIT(16 + q);
}

static inline u32 ralink_fe_tx_irq_bit(int q)
{
	return BIT(q);
}

static inline u32 ralink_fe_tx_base_ptr(int q)
{
	return TX_BASE_PTR0 + q * 0x10;
}

static inline u32 ralink_fe_tx_max_cnt(int q)
{
	return TX_MAX_CNT0 + q * 0x10;
}

static inline u32 ralink_fe_tx_ctx_idx(int q)
{
	return TX_CTX_IDX0 + q * 0x10;
}

static inline u32 ralink_fe_tx_dtx_idx(int q)
{
	return TX_DTX_IDX0 + q * 0x10;
}

static inline u32 ralink_fe_rx_base_ptr(int q)
{
	return RX_BASE_PTR0 + q * 0x10;
}

static inline u32 ralink_fe_rx_max_cnt(int q)
{
	return RX_MAX_CNT0 + q * 0x10;
}

static inline u32 ralink_fe_rx_ctx_idx(int q)
{
	return RX_CTX_IDX0 + q * 0x10;
}
static inline u32 ralink_fe_r32(struct ralink_fe_priv *priv, u32 reg)
{
	return readl(priv->base + reg);
}

static inline void
ralink_fe_w32(struct ralink_fe_priv *priv, u32 val, u32 reg)
{
	writel(val, priv->base + reg);
}

static void ralink_fe_irq_enable(struct ralink_fe_priv *priv, u32 mask)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->irq_lock, flags);
	priv->irq_mask |= mask;
	ralink_fe_w32(priv, priv->irq_mask, PDMA_INT_ENABLE);
	spin_unlock_irqrestore(&priv->irq_lock, flags);
}

static void ralink_fe_irq_disable(struct ralink_fe_priv *priv, u32 mask)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->irq_lock, flags);
	priv->irq_mask &= ~mask;
	ralink_fe_w32(priv, priv->irq_mask, PDMA_INT_ENABLE);
	spin_unlock_irqrestore(&priv->irq_lock, flags);
}

static int ralink_fe_dma_disable(struct ralink_fe_priv *priv)
{
	u32 v;

	v = ralink_fe_r32(priv, PDMA_GLO_CFG);
	v &= ~(RX_DMA_EN | TX_DMA_EN);
	ralink_fe_w32(priv, v, PDMA_GLO_CFG);

	return readl_poll_timeout(priv->base + PDMA_GLO_CFG, v,
				  !(v & (RX_DMA_BUSY | TX_DMA_BUSY)),
				  1000, 200000);
}

static void ralink_fe_dma_enable(struct ralink_fe_priv *priv)
{
	u32 v;

	/* keep core simple: no delay IRQ/coalesce */
	ralink_fe_w32(priv, 0, PDMA_DLY_INT_CFG);

	v = RX_DMA_EN | TX_DMA_EN | TX_WB_DDONE | priv->soc->pdma_bt_size;
	ralink_fe_w32(priv, v, PDMA_GLO_CFG);
}

static inline void ralink_fe_txq_error(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

	u64_stats_update_begin(&ring->syncp);
	ring->errors++;
	u64_stats_update_end(&ring->syncp);
}

static inline void ralink_fe_rxq_drop(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

	u64_stats_update_begin(&ring->syncp);
	ring->dropped++;
	u64_stats_update_end(&ring->syncp);
}

static inline void ralink_fe_txq_drop(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

	u64_stats_update_begin(&ring->syncp);
	ring->dropped++;
	u64_stats_update_end(&ring->syncp);
}

static void
ralink_fe_hw_set_mac(struct ralink_fe_priv *priv, const u8 *mac)
{
	u32 lo, hi;

	if (!priv->sdm)
		return;

	hi = ((u32)mac[0] << 8) | mac[1];
	lo = ((u32)mac[2] << 24) | ((u32)mac[3] << 16) |
	     ((u32)mac[4] << 8) | mac[5];

	regmap_write(priv->sdm, SDM_MAC_ADRH, hi);
	regmap_write(priv->sdm, SDM_MAC_ADRL, lo);
}

static void ralink_fe_rx_release_ring(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_RX_RING_SIZE; i++) {
		struct ralink_fe_rx_buf *b = &ring->buf[i];

		if (b->page) {
			page_pool_put_full_page(ring->pp, b->page, true);
			b->page = NULL;
			b->dma = 0;
		}
	}
}

static inline void ralink_fe_tx_unmap_desc(struct ralink_fe_priv *priv,
					   struct ralink_fe_tx_desc *d, u8 *map)
{
	u32 info2 = READ_ONCE(d->info2);
	u8 m = *map;

	if (TX2_DMA_SDL0_GET(info2)) {
		dma_addr_t dma = (dma_addr_t)(u32)d->info1;
		u16 len = TX2_DMA_SDL0_GET(info2);

		if (m & RALINK_FE_TX_MAP0_PAGE)
			dma_unmap_page(priv->dev, dma, len, DMA_TO_DEVICE);
		else
			dma_unmap_single(priv->dev, dma, len, DMA_TO_DEVICE);
	}

	if (TX2_DMA_SDL1_GET(info2)) {
		dma_addr_t dma = (dma_addr_t)(u32)d->info3;
		u16 len = TX2_DMA_SDL1_GET(info2);

		if (m & RALINK_FE_TX_MAP1_PAGE)
			dma_unmap_page(priv->dev, dma, len, DMA_TO_DEVICE);
		else
			dma_unmap_single(priv->dev, dma, len, DMA_TO_DEVICE);
	}

	*map = 0;
}

static void ralink_fe_tx_ring_init(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_TX_RING_SIZE; i++) {
		struct ralink_fe_tx_desc *d = &ring->desc[i];

		ring->skb[i] = NULL;
		ring->map[i] = 0;

		d->info1 = 0;
		d->info3 = 0;
		d->info4 = 0;

		/* CPU owns descriptor initially */
		WRITE_ONCE(d->info2, TX2_DMA_DONE);
	}

	ring->cpu_idx = 0;
	ring->clean_idx = 0;
}

static void ralink_fe_program_rings(struct ralink_fe_priv *priv)
{
	int q;

	/* Default PDMA TX scheduler: WRR with equal weights. */
	ralink_fe_w32(priv, PDMA_SCH_MODE(PDMA_SCH_MODE_WRR), PDMA_SCH);
	ralink_fe_w32(priv, PDMA_WRR_WT_Q0(1) | PDMA_WRR_WT_Q1(1) |
			    PDMA_WRR_WT_Q2(1) | PDMA_WRR_WT_Q3(1), PDMA_WRR);

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

		ralink_fe_tx_ring_init(priv, q);
		ralink_fe_w32(priv, ring->desc_dma, ralink_fe_tx_base_ptr(q));
		ralink_fe_w32(priv, RALINK_FE_TX_RING_SIZE, ralink_fe_tx_max_cnt(q));
		ralink_fe_w32(priv, ralink_fe_tx_irq_bit(q), PDMA_RST_CFG);
		ralink_fe_w32(priv, 0, ralink_fe_tx_ctx_idx(q));
	}

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

		ring->cpu_idx = RALINK_FE_RX_RING_SIZE - 1;
		ralink_fe_w32(priv, ring->desc_dma, ralink_fe_rx_base_ptr(q));
		ralink_fe_w32(priv, RALINK_FE_RX_RING_SIZE, ralink_fe_rx_max_cnt(q));
		ralink_fe_w32(priv, ralink_fe_rx_irq_bit(q), PDMA_RST_CFG);
		ralink_fe_w32(priv, RALINK_FE_RX_RING_SIZE - 1, ralink_fe_rx_ctx_idx(q));
	}
}

static int ralink_fe_rx_ring_refill(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	int i;

	for (i = 0; i < RALINK_FE_RX_RING_SIZE; i++) {
		struct ralink_fe_rx_desc *d = &ring->desc[i];
		struct ralink_fe_rx_buf *b = &ring->buf[i];
		struct page *page;
		dma_addr_t dma;

		page = page_pool_dev_alloc_pages(ring->pp);
		if (!page)
			return -ENOMEM;

		dma = page_pool_get_dma_addr(page);

		b->page = page;
		b->dma = dma;

		d->info1 = (u32)(dma + RALINK_FE_RX_HEADROOM_BYTES);
		WRITE_ONCE(d->info2, RX2_DMA_LS0);
	}

	ring->cpu_idx = RALINK_FE_RX_RING_SIZE - 1;

	return 0;
}

static void ralink_fe_rx_ring_publish(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

	ralink_fe_w32(priv, ring->cpu_idx, ralink_fe_rx_ctx_idx(q));
}

static void ralink_fe_napi_enable(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++)
		napi_enable(&priv->tx_ring[q].napi.napi);

	napi_enable(&priv->rx_napi_all);
}

static int ralink_fe_open(struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	int q, err;

	for (q = 0; q < priv->rxqs; q++) {
		err = ralink_fe_rx_ring_refill(priv, q);
		if (err)
			goto err_release_rx;
	}

	ralink_fe_program_rings(priv);

	for (q = 0; q < priv->rxqs; q++)
		ralink_fe_rx_ring_publish(priv, q);

	priv->irq_mask = 0;

	ralink_fe_napi_enable(priv);

	ralink_fe_w32(priv, 0xffffffff, PDMA_INT_STATUS);

	ralink_fe_dma_enable(priv);
	ralink_fe_irq_enable(priv, priv->irq_mask_all);

	netif_carrier_on(ndev);
	netif_tx_start_all_queues(ndev);

	return 0;

err_release_rx:
	for (q = 0; q < priv->rxqs; q++)
		ralink_fe_rx_release_ring(priv, q);

	return -ENOMEM;
}

static int ralink_fe_stop(struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	int q, i;

	netif_tx_stop_all_queues(ndev);

	ralink_fe_irq_disable(priv, priv->irq_mask_all);
	synchronize_irq(priv->irq);

	for (q = 0; q < priv->txqs; q++)
		napi_disable(&priv->tx_ring[q].napi.napi);

	napi_disable(&priv->rx_napi_all);

	if (ralink_fe_dma_disable(priv))
		netdev_warn(ndev, "DMA did not stop cleanly\n");

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

		for (i = 0; i < RALINK_FE_TX_RING_SIZE; i++) {
			if (ring->skb[i]) {
				dev_kfree_skb_any(ring->skb[i]);
				ring->skb[i] = NULL;
			}

			ralink_fe_tx_unmap_desc(priv, &ring->desc[i], &ring->map[i]);

			ring->desc[i].info1 = 0;
			ring->desc[i].info3 = 0;
			ring->desc[i].info4 = 0;
			WRITE_ONCE(ring->desc[i].info2, TX2_DMA_DONE);
		}

		ring->cpu_idx = 0;
		ring->clean_idx = 0;
		ralink_fe_w32(priv, 0, ralink_fe_tx_ctx_idx(q));
	}

	for (q = 0; q < priv->rxqs; q++)
		ralink_fe_rx_release_ring(priv, q);

	netif_carrier_off(ndev);

	return 0;
}

static int
ralink_fe_tx_poll_q(struct ralink_fe_priv *priv, int q, int budget)
{
	struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
	struct net_device *ndev = priv->ndev;
	struct netdev_queue *txq = netdev_get_tx_queue(ndev, q);
	u16 clean = ring->clean_idx & RALINK_FE_TX_RING_MASK;
	u16 dtx;
	int pkts = 0;
	u32 bytes = 0;

	dtx = (ralink_fe_r32(priv, ralink_fe_tx_dtx_idx(q)) & 0x0fff) &
	      RALINK_FE_TX_RING_MASK;
	dma_rmb();

	while (clean != dtx && pkts < budget) {
		struct ralink_fe_tx_desc *d = &ring->desc[clean];
		struct sk_buff *skb;
		u32 info2 = READ_ONCE(d->info2);
		bool done_last = info2 & (TX2_DMA_LS0 | TX2_DMA_LS1);

		ralink_fe_tx_unmap_desc(priv, d, &ring->map[clean]);

		skb = ring->skb[clean];
		if (done_last && skb) {
			ring->skb[clean] = NULL;
			bytes += skb->len;
			pkts++;
			consume_skb(skb);
		}

		clean = (clean + 1) & RALINK_FE_TX_RING_MASK;
	}

	ring->clean_idx = clean;

	u64_stats_update_begin(&ring->syncp);
	ring->packets += pkts;
	ring->bytes += bytes;
	u64_stats_update_end(&ring->syncp);

	netdev_tx_completed_queue(txq, pkts, bytes);

	if (netif_tx_queue_stopped(txq)) {
		u16 avail = (clean - ring->cpu_idx -
			     RALINK_FE_TX_STOP_RESERVE) & RALINK_FE_TX_RING_MASK;

		if (avail >= RALINK_FE_TX_WAKE_THRESH)
			netif_tx_wake_queue(txq);
	}

	if (pkts < budget) {
		if (napi_complete_done(&ring->napi.napi, pkts))
			ralink_fe_irq_enable(priv, ralink_fe_tx_irq_bit(q));
	}

	return pkts;
}

static void ralink_fe_tx_unwind_sg(struct ralink_fe_priv *priv,
				   struct ralink_fe_tx_ring *ring,
				   u16 first_desc, int needed_desc,
				   const u32 *info2)
{
	int i;

	for (i = 0; i < needed_desc; i++) {
		u16 didx = (first_desc + i) & RALINK_FE_TX_RING_MASK;
		struct ralink_fe_tx_desc *d = &ring->desc[didx];

		/*
		 * Reconstruct descriptor length fields so tx_unmap_desc()
		 * can unmap any segments successfully mapped before failure.
		 * Ownership stays with the CPU.
		 */
		WRITE_ONCE(d->info2, TX2_DMA_DONE | info2[i]);
		ralink_fe_tx_unmap_desc(priv, d, &ring->map[didx]);

		ring->skb[didx] = NULL;
		d->info1 = 0;
		d->info3 = 0;
		d->info4 = 0;
		WRITE_ONCE(d->info2, TX2_DMA_DONE);
	}
}

static netdev_tx_t
ralink_fe_tx_xmit_linear(struct ralink_fe_priv *priv,
			 struct ralink_fe_tx_ring *ring,
			 struct netdev_queue *txq,
			 struct sk_buff *skb, int q)
{
	u16 first_desc = ring->cpu_idx;
	u16 clean = ring->clean_idx;
	u16 avail;
	u16 new_cpu;
	struct ralink_fe_tx_desc *d = &ring->desc[first_desc];
	dma_addr_t dma;
	u16 len;
	u32 desc_info2;

	avail = (clean - first_desc - RALINK_FE_TX_STOP_RESERVE) &
		RALINK_FE_TX_RING_MASK;
	if (unlikely(avail < 1)) {
		ring->ring_full++;
		netif_tx_stop_queue(txq);
		return NETDEV_TX_BUSY;
	}

	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		if (skb_checksum_help(skb)) {
			ralink_fe_txq_drop(priv, q);
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}

	if (skb_put_padto(skb, ETH_ZLEN)) {
		ralink_fe_txq_drop(priv, q);
		return NETDEV_TX_OK;
	}

	len = skb_headlen(skb);

	dma = dma_map_single(priv->dev, skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(priv->dev, dma)))
		goto err_drop;

	ring->map[first_desc] = 0;
	ring->skb[first_desc] = skb;

	desc_info2 = TX2_DMA_SDL0(len) | TX2_DMA_LS0;

	d->info1 = (u32)dma;
	d->info3 = 0;
	d->info4 = 0;
	dma_wmb();
	WRITE_ONCE(d->info2, desc_info2);

	new_cpu = (first_desc + 1) & RALINK_FE_TX_RING_MASK;
	ring->cpu_idx = new_cpu;

	netdev_tx_sent_queue(txq, skb->len);

	if (!netdev_xmit_more() || netif_xmit_stopped(txq))
		ralink_fe_w32(priv, new_cpu, ralink_fe_tx_ctx_idx(q));

	return NETDEV_TX_OK;

err_drop:
	ralink_fe_txq_drop(priv, q);
	ralink_fe_txq_error(priv, q);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static netdev_tx_t
ralink_fe_tx_xmit_sg(struct ralink_fe_priv *priv,
		     struct ralink_fe_tx_ring *ring,
		     struct netdev_queue *txq,
		     struct sk_buff *skb, int q)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	u16 first_desc = ring->cpu_idx;
	u16 clean = ring->clean_idx;
	u16 avail;
	u16 new_cpu;
	u16 last_didx;
	u32 info2[DIV_ROUND_UP(MAX_SKB_FRAGS + 1, 2)];
	int nr_frags = shinfo->nr_frags;
	int segs = 1 + nr_frags;
	int needed_desc = (segs + 1) >> 1;
	int i, fidx;

	/*
	 * PDMA supports scatter-gather TX. Each descriptor carries up to
	 * two DMA segments, so a packet may span multiple descriptors.
	 */
	avail = (clean - first_desc - RALINK_FE_TX_STOP_RESERVE) &
		RALINK_FE_TX_RING_MASK;
	if (unlikely(avail < needed_desc)) {
		ring->ring_full++;
		netif_tx_stop_queue(txq);
		return NETDEV_TX_BUSY;
	}

	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		if (skb_checksum_help(skb)) {
			ralink_fe_txq_drop(priv, q);
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}

	if (skb_put_padto(skb, ETH_ZLEN)) {
		ralink_fe_txq_drop(priv, q);
		return NETDEV_TX_OK;
	}

	for (i = 0; i < needed_desc; i++) {
		u16 didx = (first_desc + i) & RALINK_FE_TX_RING_MASK;

		ring->map[didx] = 0;
		ring->skb[didx] = NULL;
		info2[i] = 0;
	}

	/* Head goes in slot0 of the first descriptor. */
	{
		struct ralink_fe_tx_desc *d = &ring->desc[first_desc];
		dma_addr_t dma;
		u16 len = skb_headlen(skb);

		dma = dma_map_single(priv->dev, skb->data, len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(priv->dev, dma)))
			goto err_drop;

		d->info1 = (u32)dma;
		d->info3 = 0;
		d->info4 = 0;
		info2[0] = TX2_DMA_SDL0(len);
	}

	last_didx = first_desc;

	for (fidx = 0; fidx < nr_frags; fidx++) {
		skb_frag_t *f = &shinfo->frags[fidx];
		int seg = fidx + 1;
		int didx_off = seg >> 1;
		bool last = (fidx == nr_frags - 1);
		u16 didx = (first_desc + didx_off) & RALINK_FE_TX_RING_MASK;
		struct ralink_fe_tx_desc *d = &ring->desc[didx];
		dma_addr_t dma;
		u16 len = skb_frag_size(f);

		dma = skb_frag_dma_map(priv->dev, f, 0, len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(priv->dev, dma)))
			goto err_unwind_sg;

		if (seg & 1) {
			ring->map[didx] |= RALINK_FE_TX_MAP1_PAGE;
			d->info3 = (u32)dma;
			info2[didx_off] |= TX2_DMA_SDL1(len);
			if (last)
				info2[didx_off] |= TX2_DMA_LS1;
		} else {
			ring->map[didx] |= RALINK_FE_TX_MAP0_PAGE;
			d->info1 = (u32)dma;
			info2[didx_off] |= TX2_DMA_SDL0(len);
			if (last)
				info2[didx_off] |= TX2_DMA_LS0;
		}

		if (last)
			last_didx = didx;
	}

	/* Completion frees skb from the last descriptor only. */
	ring->skb[last_didx] = skb;
	dma_wmb();

	for (i = 0; i < needed_desc; i++) {
		u16 didx = (first_desc + i) & RALINK_FE_TX_RING_MASK;

		WRITE_ONCE(ring->desc[didx].info2, info2[i]);
	}

	new_cpu = (first_desc + needed_desc) & RALINK_FE_TX_RING_MASK;
	ring->cpu_idx = new_cpu;

	netdev_tx_sent_queue(txq, skb->len);

	if (!netdev_xmit_more() || netif_xmit_stopped(txq))
		ralink_fe_w32(priv, new_cpu, ralink_fe_tx_ctx_idx(q));

	return NETDEV_TX_OK;

err_unwind_sg:
	ralink_fe_tx_unwind_sg(priv, ring, first_desc, needed_desc, info2);
	ralink_fe_txq_drop(priv, q);
	ralink_fe_txq_error(priv, q);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;

err_drop:
	ralink_fe_txq_drop(priv, q);
	ralink_fe_txq_error(priv, q);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static netdev_tx_t ralink_fe_start_xmit(struct sk_buff *skb,
					struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	struct ralink_fe_tx_ring *ring;
	struct netdev_queue *txq;
	int q;

	q = skb_get_queue_mapping(skb);
	if (unlikely(q >= priv->txqs))
		q = 0;

	ring = &priv->tx_ring[q];
	txq = netdev_get_tx_queue(ndev, q);

	if (likely(!skb_is_nonlinear(skb)))
		return ralink_fe_tx_xmit_linear(priv, ring, txq, skb, q);

	return ralink_fe_tx_xmit_sg(priv, ring, txq, skb, q);
}

/*
 * Preserve queue_mapping assigned by DSA for CPU-port traffic.
 * For non-DSA users, fall back to the normal core selection policy.
 */
static u16
ralink_fe_select_queue(struct net_device *ndev, struct sk_buff *skb,
				  struct net_device *sb_dev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	int queue;

	if (likely(netdev_uses_dsa(ndev)))
		queue = skb_get_queue_mapping(skb);
	else
		queue = netdev_pick_tx(ndev, skb, sb_dev);

	if (unlikely(queue >= priv->txqs))
		queue = 0;

	return queue;
}

static int ralink_fe_set_mac_addr(struct net_device *ndev, void *p)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	int ret;

	ret = eth_mac_addr(ndev, p);
	if (ret)
		return ret;

	ralink_fe_hw_set_mac(priv, ndev->dev_addr);

	return 0;
}

static void ralink_fe_get_stats64(struct net_device *ndev,
				  struct rtnl_link_stats64 *stats)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	unsigned int start;
	int q;

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
		u64 packets, bytes, dropped;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			packets = ring->packets;
			bytes   = ring->bytes;
			dropped = ring->dropped;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		stats->rx_packets += packets;
		stats->rx_bytes   += bytes;
		stats->rx_dropped += dropped;
	}

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
		u64 packets, bytes, dropped, errors;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			packets = ring->packets;
			bytes   = ring->bytes;
			dropped = ring->dropped;
			errors  = ring->errors;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		stats->tx_packets += packets;
		stats->tx_bytes   += bytes;
		stats->tx_dropped += dropped;
		stats->tx_errors  += errors;
	}
}

static const struct net_device_ops ralink_fe_netdev_ops = {
	.ndo_open		= ralink_fe_open,
	.ndo_stop		= ralink_fe_stop,
	.ndo_start_xmit		= ralink_fe_start_xmit,
	.ndo_select_queue	= ralink_fe_select_queue,
	.ndo_set_mac_address	= ralink_fe_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats64	= ralink_fe_get_stats64,
};

static inline
int ralink_fe_rx_consume_one(struct ralink_fe_priv *priv, int q,
					   u32 *bytes)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	struct net_device *ndev = priv->ndev;
	u16 cpu = (ring->cpu_idx + 1) & RALINK_FE_RX_RING_MASK;
	struct ralink_fe_rx_desc *d = &ring->desc[cpu];
	struct ralink_fe_rx_buf *b = &ring->buf[cpu];
	struct sk_buff *skb;
	struct page *page;
	dma_addr_t dma;
	u32 info2, rxsum, len;

	*bytes = 0;

	info2 = READ_ONCE(d->info2);
	if (!(info2 & RX2_DMA_DONE))
		return 0;

	dma_rmb();
	rxsum = READ_ONCE(d->info4);
	len = RX2_DMA_SDL0_GET(info2);

	page = page_pool_dev_alloc_pages(ring->pp);
	if (unlikely(!page)) {
		ring->refill_fail++;
		ralink_fe_rxq_drop(priv, q);

		page = b->page;
		dma = b->dma;
		goto rx_rearm;
	}

	dma = page_pool_get_dma_addr(page);

	dma_sync_single_for_cpu(priv->dev,
				b->dma + RALINK_FE_RX_HEADROOM_BYTES,
				len, DMA_FROM_DEVICE);

	skb = napi_build_skb(page_address(b->page), PAGE_SIZE);
	if (unlikely(!skb)) {
		ralink_fe_rxq_drop(priv, q);
		page_pool_put_full_page(ring->pp, b->page, true);
		goto rx_rearm;
	}

	skb_mark_for_recycle(skb);
	skb_reserve(skb, RALINK_FE_RX_HEADROOM_BYTES);
	skb_put(skb, len);

	if ((rxsum & RX4_DMA_L4FVLD) &&
	    !(rxsum & RX4_DMA_L4F) &&
	    !(rxsum & RX4_DMA_IPF))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else
		skb_checksum_none_assert(skb);

	skb->protocol = eth_type_trans(skb, ndev);
	skb_record_rx_queue(skb, q);
	napi_gro_receive(&priv->rx_napi_all, skb);

	*bytes = len;

rx_rearm:
	b->page = page;
	b->dma = dma;

	d->info1 = (u32)(dma + RALINK_FE_RX_HEADROOM_BYTES);
	/*
	 * Single-buffer RX descriptor:
	 * SDP0 points at the receive buffer, LS0 marks it as the
	 * last/only segment, and DDONE is cleared for device ownership.
	 */
	WRITE_ONCE(d->info2, RX2_DMA_LS0);

	ring->cpu_idx = cpu;
	return 1;
}

static int ralink_fe_rx_poll_all(struct napi_struct *napi, int budget)
{
	struct ralink_fe_priv *priv =
		container_of(napi, struct ralink_fe_priv, rx_napi_all);
	u32 mmio_mask = 0;
	u32 rx_pkts[RALINK_FE_MAX_RXQ] = {};
	u32 rx_bytes[RALINK_FE_MAX_RXQ] = {};
	int work_done = 0;
	int q = 0;
	int idle = 0;
	int i;

	while (work_done < budget && idle < priv->rxqs) {
		u32 bytes;

		if (ralink_fe_rx_consume_one(priv, q, &bytes)) {
			work_done++;
			idle = 0;
			mmio_mask |= BIT(q);

			if (bytes) {
				rx_pkts[q]++;
				rx_bytes[q] += bytes;
			}
		} else {
			idle++;
		}

		if (++q == priv->rxqs)
			q = 0;
	}

	for (i = 0; i < priv->rxqs; i++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[i];

		if (!rx_pkts[i])
			continue;

		u64_stats_update_begin(&ring->syncp);
		ring->packets += rx_pkts[i];
		ring->bytes += rx_bytes[i];
		u64_stats_update_end(&ring->syncp);
	}

	if (mmio_mask) {
		dma_wmb();

		for (i = 0; i < priv->rxqs; i++) {
			if (mmio_mask & BIT(i))
				ralink_fe_w32(priv, priv->rx_ring[i].cpu_idx,
					      ralink_fe_rx_ctx_idx(i));
		}
	}

	if (work_done < budget) {
		if (napi_complete_done(&priv->rx_napi_all, work_done))
			ralink_fe_irq_enable(priv, priv->rx_irq_mask);
	}

	return work_done;
}

static int ralink_fe_tx_poll(struct napi_struct *napi, int budget)
{
	struct ralink_fe_qnapi *qn =
		container_of(napi, struct ralink_fe_qnapi, napi);

	return ralink_fe_tx_poll_q(qn->priv, qn->q, budget);
}

static irqreturn_t ralink_fe_irq(int irq, void *data)
{
	struct ralink_fe_priv *priv = data;
	u32 st = ralink_fe_r32(priv, PDMA_INT_STATUS) & READ_ONCE(priv->irq_mask);
	irqreturn_t ret = IRQ_NONE;
	int nq = max_t(int, priv->txqs, priv->rxqs);
	bool rx = false;
	int q;

	if (!st)
		return IRQ_NONE;

	ralink_fe_irq_disable(priv, st);
	ralink_fe_w32(priv, st, PDMA_INT_STATUS);

	for (q = 0; q < nq; q++) {
		if (q < priv->rxqs && (st & ralink_fe_rx_irq_bit(q))) {
			rx = true;
			ret = IRQ_HANDLED;
		}

		if (q < priv->txqs && (st & ralink_fe_tx_irq_bit(q))) {
			if (napi_schedule_prep(&priv->tx_ring[q].napi.napi)) {
				__napi_schedule(&priv->tx_ring[q].napi.napi);
				ret = IRQ_HANDLED;
			}
		}
	}

	if (rx && napi_schedule_prep(&priv->rx_napi_all))
		__napi_schedule(&priv->rx_napi_all);

	return ret;
}

static void ralink_fe_get_drvinfo(struct net_device *ndev,
				  struct ethtool_drvinfo *info)
{
	strscpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strscpy(info->version, UTS_RELEASE, sizeof(info->version));
	strscpy(info->bus_info, dev_name(ndev->dev.parent),
		sizeof(info->bus_info));
}

static u32 ralink_fe_get_msglevel(struct net_device *ndev)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	return priv->msg_enable;
}

static void ralink_fe_set_msglevel(struct net_device *ndev, u32 value)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	priv->msg_enable = value;
}

static void ralink_fe_get_ringparam(struct net_device *ndev,
				    struct ethtool_ringparam *ring,
				    struct kernel_ethtool_ringparam *kernel_ring,
				    struct netlink_ext_ack *extack)
{
	ring->rx_max_pending = RALINK_FE_RX_RING_SIZE;
	ring->tx_max_pending = RALINK_FE_TX_RING_SIZE;
	ring->rx_pending = RALINK_FE_RX_RING_SIZE;
	ring->tx_pending = RALINK_FE_TX_RING_SIZE;
}

static int ralink_fe_get_sset_count(struct net_device *ndev, int sset)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);

	if (sset != ETH_SS_STATS)
		return -EOPNOTSUPP;

	return priv->txqs * 5 + priv->rxqs * 4;
}

static void
ralink_fe_get_strings(struct net_device *ndev, u32 sset, u8 *data)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	unsigned int q;

	if (sset != ETH_SS_STATS)
		return;

	for (q = 0; q < priv->txqs; q++) {
		ethtool_sprintf(&data, "tx_queue_%u_packets", q);
		ethtool_sprintf(&data, "tx_queue_%u_bytes", q);
		ethtool_sprintf(&data, "tx_queue_%u_errors", q);
		ethtool_sprintf(&data, "tx_queue_%u_dropped", q);
		ethtool_sprintf(&data, "tx_queue_%u_ring_full", q);
	}

	for (q = 0; q < priv->rxqs; q++) {
		ethtool_sprintf(&data, "rx_queue_%u_packets", q);
		ethtool_sprintf(&data, "rx_queue_%u_bytes", q);
		ethtool_sprintf(&data, "rx_queue_%u_dropped", q);
		ethtool_sprintf(&data, "rx_queue_%u_refill_fail", q);
	}
}

static void ralink_fe_get_ethtool_stats(struct net_device *ndev,
					struct ethtool_stats *stats, u64 *data)
{
	struct ralink_fe_priv *priv = netdev_priv(ndev);
	unsigned int q, i = 0;

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];
		unsigned int start;
		u64 pkts, bytes, errors, dropped;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			pkts = ring->packets;
			bytes = ring->bytes;
			errors = ring->errors;
			dropped = ring->dropped;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = errors;
		data[i++] = dropped;
		data[i++] = READ_ONCE(ring->ring_full);
	}

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
		unsigned int start;
		u64 pkts, bytes, dropped;

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			pkts = ring->packets;
			bytes = ring->bytes;
			dropped = ring->dropped;
		} while (u64_stats_fetch_retry(&ring->syncp, start));

		data[i++] = pkts;
		data[i++] = bytes;
		data[i++] = dropped;
		data[i++] = READ_ONCE(ring->refill_fail);
	}
}

const struct ethtool_ops ralink_fe_ethtool_ops = {
	.get_drvinfo		= ralink_fe_get_drvinfo,
	.get_msglevel		= ralink_fe_get_msglevel,
	.set_msglevel		= ralink_fe_set_msglevel,
	.get_link		= ethtool_op_get_link,
	.get_ringparam		= ralink_fe_get_ringparam,
	.get_sset_count		= ralink_fe_get_sset_count,
	.get_strings		= ralink_fe_get_strings,
	.get_ethtool_stats	= ralink_fe_get_ethtool_stats,
};

static void ralink_fe_setup_netdev(struct net_device *ndev,
				   struct ralink_fe_priv *priv)
{
	struct device *dev = priv->dev;
	int err;

	err = of_get_ethdev_address(dev->of_node, ndev);
	if (err)
		eth_hw_addr_random(ndev);

	ralink_fe_hw_set_mac(priv, ndev->dev_addr);

	ndev->hw_features = NETIF_F_RXCSUM | NETIF_F_SG;
	ndev->features = ndev->hw_features;

	ndev->max_mtu = RALINK_FE_MAX_DMA_LEN - VLAN_ETH_HLEN;
	ndev->netdev_ops = &ralink_fe_netdev_ops;
	ndev->ethtool_ops = &ralink_fe_ethtool_ops;

	priv->msg_enable = NETIF_MSG_DRV |
			   NETIF_MSG_PROBE |
			   NETIF_MSG_IFUP;
}

static int ralink_fe_pp_create(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];
	struct page_pool_params pp = {
		.flags     = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.order     = 0,
		.pool_size = RALINK_FE_RX_RING_SIZE + (RALINK_FE_RX_RING_SIZE / 2),
		.nid       = NUMA_NO_NODE,
		.dev       = priv->dev,
		.dma_dir   = DMA_FROM_DEVICE,
		.max_len   = RALINK_FE_MAX_DMA_LEN,
		.offset    = RALINK_FE_RX_HEADROOM_BYTES,
	};

	ring->pp = page_pool_create(&pp);
	if (IS_ERR(ring->pp)) {
		int err = PTR_ERR(ring->pp);

		ring->pp = NULL;
		return err;
	}

	return 0;
}

static void ralink_fe_pp_destroy(struct ralink_fe_priv *priv, int q)
{
	struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

	if (ring->pp) {
		page_pool_destroy(ring->pp);
		ring->pp = NULL;
	}
}

static int ralink_fe_init_page_pools(struct ralink_fe_priv *priv)
{
	int q, err;

	for (q = 0; q < priv->rxqs; q++) {
		err = ralink_fe_pp_create(priv, q);
		if (err)
			goto err;
	}

	return 0;

err:
	while (--q >= 0)
		ralink_fe_pp_destroy(priv, q);

	return err;
}

static void ralink_fe_cleanup_page_pools(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->rxqs; q++)
		ralink_fe_pp_destroy(priv, q);
}

static void ralink_fe_setup_sdm(struct ralink_fe_priv *priv)
{
	u32 v;

	if (priv->sdm) {
		v = SDM_PDMA_FC | SDM_PORT_MAP | SDM_TCI_81XX |
		    FIELD_PREP(SDM_EXT_VLAN, 0x8100);
		v &= ~(SDM_UDPCS | SDM_TCPCS | SDM_IPCS);
		regmap_write(priv->sdm, SDM_CON, v);
	}
}

static int ralink_fe_init_queues(struct net_device *ndev,
				 struct ralink_fe_priv *priv)
{
	u32 tx_irq_mask = 0;
	int q;

	priv->rx_irq_mask = 0;

	for (q = 0; q < priv->rxqs; q++) {
		struct ralink_fe_rx_ring *ring = &priv->rx_ring[q];

		priv->rx_irq_mask |= ralink_fe_rx_irq_bit(q);
		u64_stats_init(&ring->syncp);
	}

	for (q = 0; q < priv->txqs; q++) {
		struct ralink_fe_tx_ring *ring = &priv->tx_ring[q];

		tx_irq_mask |= ralink_fe_tx_irq_bit(q);
		u64_stats_init(&ring->syncp);
	}

	priv->irq_mask_all = priv->rx_irq_mask | tx_irq_mask;

	for (q = 0; q < priv->txqs; q++) {
		priv->tx_ring[q].napi.priv = priv;
		priv->tx_ring[q].napi.q = q;

		netif_napi_add_tx_weight(ndev,
			&priv->tx_ring[q].napi.napi,
			ralink_fe_tx_poll,
			RALINK_FE_NAPI_TX);
	}

	netif_napi_add_weight(ndev,
		&priv->rx_napi_all,
		ralink_fe_rx_poll_all,
		RALINK_FE_NAPI_RX);

	return 0;
}

static void ralink_fe_napi_cleanup(struct ralink_fe_priv *priv)
{
	int q;

	for (q = 0; q < priv->txqs; q++)
		netif_napi_del(&priv->tx_ring[q].napi.napi);

	netif_napi_del(&priv->rx_napi_all);
}

static int ralink_fe_hw_init(struct platform_device *pdev,
			     struct ralink_fe_priv *priv)
{
	struct device *dev = &pdev->dev;
	struct device_node *sdm_np;
	int err;

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return dev_err_probe(dev, PTR_ERR(priv->base),
				     "failed to map registers");

	priv->irq = platform_get_irq(pdev, 0);
	if (priv->irq < 0)
		return dev_err_probe(dev, priv->irq, "missing IRQ");

	priv->clk = devm_clk_get_optional(dev, "fe");
	if (IS_ERR(priv->clk))
		return dev_err_probe(dev, PTR_ERR(priv->clk),
				     "failed to get fe clock");

	err = clk_prepare_enable(priv->clk);
	if (err)
		return dev_err_probe(dev, err,
				     "failed to enable fe clock");

	priv->rst_fe = devm_reset_control_get_optional_exclusive(dev, "fe");
	if (IS_ERR(priv->rst_fe)) {
		err = dev_err_probe(dev, PTR_ERR(priv->rst_fe),
				    "failed to get fe reset");
		goto err_clk;
	}

	if (priv->rst_fe) {
		err = reset_control_deassert(priv->rst_fe);
		if (err) {
			err = dev_err_probe(dev, err,
					    "failed to deassert fe reset");
			goto err_clk;
		}
	}

	sdm_np = of_parse_phandle(dev->of_node, "ralink,sdm", 0);
	if (!sdm_np) {
		if (priv->soc->needs_sdm) {
			err = dev_err_probe(dev, -EINVAL,
				     "missing required ralink,sdm phandle");
			goto err_reset;
		}

		priv->sdm = NULL;
		return 0;
	}

	priv->sdm = syscon_node_to_regmap(sdm_np);
	of_node_put(sdm_np);

	if (IS_ERR(priv->sdm)) {
		err = dev_err_probe(dev, PTR_ERR(priv->sdm),
				    "failed to get SDM regmap");
		goto err_reset;
	}

	ralink_fe_setup_sdm(priv);

	return 0;

err_reset:
	if (priv->rst_fe)
		reset_control_assert(priv->rst_fe);
err_clk:
	clk_disable_unprepare(priv->clk);
	return err;
}

static void ralink_fe_hw_cleanup(struct ralink_fe_priv *priv)
{
	if (priv->rst_fe)
		reset_control_assert(priv->rst_fe);

	if (priv->clk)
		clk_disable_unprepare(priv->clk);
}

static int ralink_fe_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct ralink_fe_soc_data *soc;
	struct net_device *ndev;
	struct ralink_fe_priv *priv;
	int err;

	soc = of_device_get_match_data(dev);
	if (!soc)
		return dev_err_probe(dev, -EINVAL, "missing match data\n");

	ndev = devm_alloc_etherdev_mqs(dev, sizeof(*priv),
				       soc->txqs, soc->rxqs);
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, dev);

	priv = netdev_priv(ndev);
	priv->dev = dev;
	priv->ndev = ndev;
	priv->soc = soc;
	priv->txqs = soc->txqs;
	priv->rxqs = soc->rxqs;

	err = ralink_fe_hw_init(pdev, priv);
	if (err)
		return err;

	err = ralink_fe_init_queues(ndev, priv);
	if (err)
		goto err_hw;

	err = ralink_fe_init_page_pools(priv);
	if (err)
		goto err_napi;

	ralink_fe_setup_netdev(ndev, priv);

	platform_set_drvdata(pdev, priv);

	ralink_fe_dma_disable(priv);
	ralink_fe_w32(priv, 0xffffffff, PDMA_INT_STATUS);
	ralink_fe_w32(priv, 0, PDMA_INT_ENABLE);

	err = devm_request_irq(dev, priv->irq, ralink_fe_irq, 0,
			       dev_name(dev), priv);
	if (err) {
		err = dev_err_probe(dev, err, "failed to request IRQ");
		goto err_pp;
	}

	err = register_netdev(ndev);
	if (err)
		goto err_pp;

	dev_info(dev, "Ralink FE: %u TXQ / %u RXQ\n", priv->txqs, priv->rxqs);

	return 0;

err_pp:
	ralink_fe_cleanup_page_pools(priv);
err_napi:
	ralink_fe_napi_cleanup(priv);
err_hw:
	ralink_fe_hw_cleanup(priv);
	return err;
}

static void ralink_fe_remove(struct platform_device *pdev)
{
	struct ralink_fe_priv *priv = platform_get_drvdata(pdev);

	unregister_netdev(priv->ndev);
	ralink_fe_cleanup_page_pools(priv);
	ralink_fe_hw_cleanup(priv);
}

static const struct ralink_fe_soc_data rt5350_data = {
	.txqs = 4,
	.rxqs = 2,
	.needs_sdm = true,
	.pdma_bt_size = PDMA_BT_SIZE_8WORDS,
};

static const struct ralink_fe_soc_data mt7628_data = {
	.txqs = 4,
	.rxqs = 2,
	.needs_sdm = true,
	.pdma_bt_size = PDMA_BT_SIZE_16WORDS,
};

static const struct of_device_id ralink_fe_of_match[] = {
	{ .compatible = "ralink,rt5350-fe", .data = &rt5350_data },
	{ .compatible = "mediatek,mt7628-fe", .data = &mt7628_data },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, ralink_fe_of_match);

static struct platform_driver ralink_fe_driver = {
	.probe = ralink_fe_probe,
	.remove = ralink_fe_remove,
	.driver = {
		.name = "ralink_fe",
		.of_match_table = ralink_fe_of_match,
	},
};
module_platform_driver(ralink_fe_driver);

MODULE_AUTHOR("Richard van Schagen <richard@routerwrt.org>");
MODULE_DESCRIPTION("NIC driver for the Ralink/MediaTek FE");
MODULE_LICENSE("GPL");
