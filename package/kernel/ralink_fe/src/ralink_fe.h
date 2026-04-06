/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RALINK_FE_H
#define __RALINK_FE_H

/* --- configurable --- */
#define RALINK_FE_TX_RING_SIZE		128
#define RALINK_FE_RX_RING_SIZE		256

#define RALINK_FE_NAPI_RX		32
#define RALINK_FE_NAPI_TX		32

#define RALINK_FE_TX_STOP_RESERVE	16
#define RALINK_FE_TX_WAKE_THRESH	16

/* Power-of-2 masks */
#define RALINK_FE_TX_RING_MASK		(RALINK_FE_TX_RING_SIZE - 1)
#define RALINK_FE_RX_RING_MASK		(RALINK_FE_RX_RING_SIZE - 1)

/* explicit headroom, independent from RALINK_FE_MAX_DMA_LEN */
#define RALINK_FE_RX_HEADROOM_BYTES     (64 + NET_IP_ALIGN)
#define RALINK_FE_MAX_DMA_LEN		(1536)
#define RALINK_FE_RX_DMA_SIZE		\
	(RALINK_FE_RX_HEADROOM_BYTES + RALINK_FE_MAX_DMA_LEN)
#define RALINK_FE_MAX_TXQ		4
#define RALINK_FE_MAX_RXQ		2

/* ---- Base offsets ---- */
#define PDMA_OFFSET			0x0800

#define PDMA_GLO_CFG			(PDMA_OFFSET + 0x204)
#define PDMA_RST_CFG			(PDMA_OFFSET + 0x208)
#define PDMA_DLY_INT_CFG		(PDMA_OFFSET + 0x20C)
#define PDMA_INT_STATUS			(PDMA_OFFSET + 0x220)
#define PDMA_INT_ENABLE			(PDMA_OFFSET + 0x228)

#define TX_BASE_PTR0			(PDMA_OFFSET + 0x000)
#define TX_MAX_CNT0			(PDMA_OFFSET + 0x004)
#define TX_CTX_IDX0			(PDMA_OFFSET + 0x008)
#define TX_DTX_IDX0			(PDMA_OFFSET + 0x00C)

#define RX_BASE_PTR0			(PDMA_OFFSET + 0x100)
#define RX_MAX_CNT0			(PDMA_OFFSET + 0x104)
#define RX_CTX_IDX0			(PDMA_OFFSET + 0x108)

/* ---- PDMA GLO bits ---- */
#define TX_WB_DDONE			BIT(6)
#define RX_DMA_BUSY			BIT(3)
#define RX_DMA_EN			BIT(2)
#define TX_DMA_BUSY			BIT(1)
#define TX_DMA_EN			BIT(0)

#define PDMA_BT_SIZE_8WORDS		(1 << 4)
#define PDMA_BT_SIZE_16WORDS		(2 << 4)

/* PDMA TX scheduling */
#define PDMA_SCH		(PDMA_OFFSET + 0x280)
#define PDMA_WRR		(PDMA_OFFSET + 0x284)
#define PDMA_SCH_MODE_MASK	GENMASK(25, 24)
#define  PDMA_SCH_MODE_WRR	0x0
#define PDMA_SCH_MODE(v)	FIELD_PREP(PDMA_SCH_MODE_MASK, (v))
#define PDMA_WRR_WT_Q0_MASK	GENMASK(2, 0)
#define PDMA_WRR_WT_Q1_MASK	GENMASK(6, 4)
#define PDMA_WRR_WT_Q2_MASK	GENMASK(10, 8)
#define PDMA_WRR_WT_Q3_MASK	GENMASK(14, 12)
#define PDMA_WRR_WT_Q0(v)	FIELD_PREP(PDMA_WRR_WT_Q0_MASK, (v))
#define PDMA_WRR_WT_Q1(v)	FIELD_PREP(PDMA_WRR_WT_Q1_MASK, (v))
#define PDMA_WRR_WT_Q2(v)	FIELD_PREP(PDMA_WRR_WT_Q2_MASK, (v))
#define PDMA_WRR_WT_Q3(v)	FIELD_PREP(PDMA_WRR_WT_Q3_MASK, (v))

/* SDM – Switch DMA glue block */

/* SDM registers */
#define SDM_CON			0x0000
#define SDM_MAC_ADRL		0x000c
#define SDM_MAC_ADRH		0x0010
#define SDM_MAC_ADRH_MASK	GENMASK(15, 0)

#define SDM_PDMA_FC		BIT(23)
#define SDM_PORT_MAP		BIT(22)
#define SDM_TCI_81XX		BIT(20)
#define SDM_UDPCS		BIT(18)
#define SDM_TCPCS		BIT(17)
#define SDM_IPCS		BIT(16)
#define SDM_EXT_VLAN		GENMASK(15, 0)

/* ---- descriptors ---- */
struct ralink_fe_tx_desc {
	u32 info1; /* addr0 */
	u32 info2; /* len0/len1/flags/done */
	u32 info3; /* addr1 */
	u32 info4; /* reserved (kept 0 for cross-SoC compatibility) */
};

#define TX2_DMA_SDL1_MASK	GENMASK(13, 0)
#define TX2_DMA_LS1		BIT(14)
#define TX2_DMA_SDL0_MASK	GENMASK(29, 16)
#define TX2_DMA_LS0		BIT(30)
#define TX2_DMA_DONE		BIT(31)

#define TX2_DMA_SDL1(_x)	FIELD_PREP(TX2_DMA_SDL1_MASK, (_x))
#define TX2_DMA_SDL0(_x)	FIELD_PREP(TX2_DMA_SDL0_MASK, (_x))
#define TX2_DMA_SDL1_GET(_x)	FIELD_GET(TX2_DMA_SDL1_MASK, (_x))
#define TX2_DMA_SDL0_GET(_x)	FIELD_GET(TX2_DMA_SDL0_MASK, (_x))

struct ralink_fe_rx_desc {
	u32 info1; /* addr */
	u32 info2; /* len/flags/done */
	u32 info3;
	u32 info4; /* checksum flags etc. */
};

#define RX2_DMA_SDL1_MASK	GENMASK(13, 0)
#define RX2_DMA_SDL0_MASK	GENMASK(29, 16)
#define RX2_DMA_LS0		BIT(30)
#define RX2_DMA_DONE		BIT(31)

#define RX2_DMA_SDL1(_x)	FIELD_PREP(RX2_DMA_SDL1_MASK, (_x))
#define RX2_DMA_SDL0(_x)	FIELD_PREP(RX2_DMA_SDL0_MASK, (_x))
#define RX2_DMA_SDL1_GET(_x)	FIELD_GET(RX2_DMA_SDL1_MASK, (_x))
#define RX2_DMA_SDL0_GET(_x)	FIELD_GET(RX2_DMA_SDL0_MASK, (_x))

/*
 * RX4_DMA_L4FVLD means the L4 checksum result is valid for this packet
 * (IPv4, no fragments, TCP/UDP). RX4_DMA_L4F indicates checksum failure.
 */
#define RX4_DMA_IPFVLD		BIT(31)
#define RX4_DMA_L4FVLD		BIT(30)
#define RX4_DMA_IPF		BIT(29)
#define RX4_DMA_L4F		BIT(28)
#define RX4_DMA_SP		GENMASK(26, 24)
#define RX4_DMA_PAR_RLT		GENMASK(23, 16)
#define RX4_DMA_ADR		GENMASK(1, 0)

/* ---- private ---- */
#define RALINK_FE_TX_MAP0_PAGE  BIT(0)
#define RALINK_FE_TX_MAP1_PAGE  BIT(1)

struct ralink_fe_soc_data {
	u8				txqs;
	u8				rxqs;
	bool				needs_sdm;
	u32				pdma_bt_size;
};

/* Per-queue NAPI wrapper so poll callbacks can recover the queue index. */
struct ralink_fe_qnapi {
	struct napi_struct		napi;
	struct ralink_fe_priv		*priv;
	u8				q;
};

struct ralink_fe_tx_ring {
	struct ralink_fe_tx_desc	*desc;
	dma_addr_t			desc_dma;

	u16				cpu_idx;
	u16				clean_idx;

	struct sk_buff			*skb[RALINK_FE_TX_RING_SIZE];
	u8				map[RALINK_FE_TX_RING_SIZE];

	struct ralink_fe_qnapi		napi;

	struct u64_stats_sync		syncp;
	u64				packets;
	u64				bytes;
	u64				errors;
	u64				dropped;

	u32				ring_full;
};

/* RX buffer (full page) */
struct ralink_fe_rx_buf {
	struct page			*page;
	dma_addr_t			dma;
};

struct ralink_fe_rx_ring {
	struct ralink_fe_rx_desc	*desc;
	dma_addr_t			desc_dma;

	u16				cpu_idx;

	struct page_pool		*pp;
	struct ralink_fe_rx_buf		buf[RALINK_FE_RX_RING_SIZE];

	struct u64_stats_sync		syncp;
	u64				packets;
	u64				bytes;
	u64				dropped;

	u32				refill_fail;
};

struct ralink_fe_priv {
	void __iomem			*base;
	struct device			*dev;
	struct net_device		*ndev;

	const struct ralink_fe_soc_data	*soc;

	struct clk			*clk;
	struct reset_control		*rst_fe;
	struct regmap			*sdm;
	int				irq;
	spinlock_t			irq_lock;
	u32				irq_mask;
	u32				rx_irq_mask;
	u32				irq_mask_all;

	u8				txqs;
	u8				rxqs;

	struct ralink_fe_tx_ring	tx_ring[RALINK_FE_MAX_TXQ];
	struct ralink_fe_rx_ring	rx_ring[RALINK_FE_MAX_RXQ];
	struct napi_struct		rx_napi_all;

	u32				msg_enable;
};

#endif /* __RALINK_FE_H */
