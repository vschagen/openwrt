/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RALINK_ESW_DSA_H_
#define _RALINK_ESW_DSA_H_

#include <linux/if_vlan.h>
#include <linux/regmap.h>
#include <linux/workqueue.h>

#define RALINK_ESW_MDIO_TIMEOUT_US		1000
#define RALINK_ESW_STATS_POLL_INTERVAL		(2 * HZ)
#define RALINK_ESW_ATU_TIMEOUT_US		1000

#define RALINK_ESW_NUM_PORTS			7
#define RALINK_ESW_MAX_FRAME_LEN		1522
#define RALINK_ESW_MAX_MTU \
	(RALINK_ESW_MAX_FRAME_LEN - ETH_HLEN - VLAN_HLEN)

#define RALINK_ESW_NUM_VLANS			16
#define RALINK_ESW_VID_NONE			0

#define SDM_RRING				0x0004
#define   SDM_PRIO_RING_MASK			GENMASK(7, 0)
#define   SDM_PRIO_RING_BIT(prio)		BIT(prio)
#define   SDM_PORT_RING_MASK			GENMASK(12, 8) /* port0..4 */
#define   SDM_PORT_RING_SHIFT			8
#define   SDM_PORT_RING_BIT(port)		BIT(SDM_PORT_RING_SHIFT + (port))

#define RALINK_ESW_ISR				0x0000
#define RALINK_ESW_IMR				0x0004
#define   RALINK_ESW_PORT_ST_CHG		BIT(26)

#define RALINK_ESW_PCR0				0x00c0
#define   RALINK_ESW_PCR0_PHY_ADDR		GENMASK(4, 0)
#define   RALINK_ESW_PCR0_PHY_REG		GENMASK(12, 8)
#define   RALINK_ESW_PCR0_WT_PHY_CMD		BIT(13)
#define   RALINK_ESW_PCR0_RD_PHY_CMD		BIT(14)
#define   RALINK_ESW_PCR0_WT_DATA		GENMASK(31, 16)

#define RALINK_ESW_PCR1				0x00c4
#define   RALINK_ESW_PCR1_WT_DONE		BIT(0)
#define   RALINK_ESW_PCR1_RD_RDY		BIT(1)
#define   RALINK_ESW_PCR1_RD_DATA		GENMASK(31, 16)

#define RALINK_ESW_FPA				0x0084
#define   RALINK_ESW_FPA_FORCE_MODE_SHIFT	27
#define   RALINK_ESW_FPA_FORCE_LNK_SHIFT	22
#define   RALINK_ESW_FPA_FORCE_XFC_SHIFT	16
#define   RALINK_ESW_FPA_FORCE_DPX_SHIFT	8
#define   RALINK_ESW_FPA_FORCE_SPD_SHIFT	0

#define RALINK_ESW_FPA1				0x00c8
#define   RALINK_ESW_FPA1_FORCE_LNK0		BIT(12)
#define   RALINK_ESW_FPA1_FORCE_LNK1		BIT(13)
#define   RALINK_ESW_FPA1_FORCE_EN0		BIT(10)
#define   RALINK_ESW_FPA1_FORCE_EN1		BIT(11)
#define   RALINK_ESW_FPA1_FORCE_DPX0		BIT(4)
#define   RALINK_ESW_FPA1_FORCE_DPX1		BIT(5)
#define   RALINK_ESW_FPA1_FORCE_XFC0_SHIFT	6
#define   RALINK_ESW_FPA1_FORCE_XFC1_SHIFT	8
#define   RALINK_ESW_FPA1_FORCE_SPD0_SHIFT	0
#define   RALINK_ESW_FPA1_FORCE_SPD1_SHIFT	2
#define   RALINK_ESW_FPA1_FORCE_XFC0		GENMASK(7, 6)
#define   RALINK_ESW_FPA1_FORCE_XFC1		GENMASK(9, 8)
#define   RALINK_ESW_FPA1_FORCE_SPD0		GENMASK(1, 0)
#define   RALINK_ESW_FPA1_FORCE_SPD1		GENMASK(3, 2)

#define RALINK_ESW_POA				0x0080
#define   RALINK_ESW_POA_LINK_SHIFT		25

#define RALINK_ESW_POC0				0x0090
#define   RALINK_ESW_POC0_DIS_PORT_SHIFT	23

#define RALINK_ESW_PFC1				0x0014
#define   RALINK_ESW_PFC1_CPU_USE_Q1_EN		BIT(31)
#define   RALINK_ESW_PFC1_EN_TOS		GENMASK(30, 24)
#define   RALINK_ESW_PFC1_EN_TOS_SHIFT		24
#define   RALINK_ESW_PFC1_EN_VLAN		GENMASK(22, 16)
#define   RALINK_ESW_PFC1_EN_VLAN_SHIFT		16
#define   RALINK_ESW_PFC1_PRIORITY_OPTION	BIT(15)
#define   RALINK_ESW_PFC1_IGMP_SNOOP		BIT(14)

#define   RALINK_ESW_PFC1_PORT_PRI_SHIFT(port)	((port) * 2)
#define   RALINK_ESW_PFC1_PORT_PRI_MASK(port)	\
	(0x3u << RALINK_ESW_PFC1_PORT_PRI_SHIFT(port))
#define   RALINK_ESW_PFC1_PORT_PRI_VAL(port, pri) \
	((u32)(pri) << RALINK_ESW_PFC1_PORT_PRI_SHIFT(port))

#define RALINK_ESW_PFC1_EN_VLAN_BIT(port) \
	BIT(RALINK_ESW_PFC1_EN_VLAN_SHIFT + (port))

#define RALINK_ESW_PFC1_EN_TOS_BIT(port) \
	BIT(RALINK_ESW_PFC1_EN_TOS_SHIFT + (port))

#define RALINK_ESW_SOCPC			0x008c
#define   RALINK_ESW_SOCPC_CRC_PADDING		BIT(25)
#define   RALINK_ESW_SOCPC_CPU_SELECTION	GENMASK(24, 23)
#define   RALINK_ESW_SOCPC_DISBC2CPU		GENMASK(22, 16)
#define   RALINK_ESW_SOCPC_DISMC2CPU		GENMASK(14, 8)
#define   RALINK_ESW_SOCPC_DISUN2CPU		GENMASK(6, 0)

#define   RALINK_ESW_SOCPC_DISUN2CPU_SHIFT	0
#define   RALINK_ESW_SOCPC_DISMC2CPU_SHIFT	8
#define   RALINK_ESW_SOCPC_DISBC2CPU_SHIFT	16

#define RALINK_ESW_SOCPC_DISUN2CPU_BIT(port) \
	BIT(RALINK_ESW_SOCPC_DISUN2CPU_SHIFT + (port))

#define RALINK_ESW_SOCPC_DISMC2CPU_BIT(port) \
	BIT(RALINK_ESW_SOCPC_DISMC2CPU_SHIFT + (port))

#define RALINK_ESW_SOCPC_DISBC2CPU_BIT(port) \
	BIT(RALINK_ESW_SOCPC_DISBC2CPU_SHIFT + (port))

#define RALINK_ESW_SGC				0x009c
#define   RALINK_ESW_SGC_BKOFF_ALG		BIT(30)
#define   RALINK_ESW_SGC_LEN_ERR_CHK		BIT(29)
#define   RALINK_ESW_SGC_IP_MULT_RULE		GENMASK(28, 27)
#define   RALINK_ESW_SGC_RMC_RULE		GENMASK(26, 25)
#define   RALINK_ESW_SGC_LED_FLASH_TIME		GENMASK(24, 23)
#define   RALINK_ESW_SGC_BISH_TH		GENMASK(22, 21)
#define   RALINK_ESW_SGC_BISH_DIS		BIT(20)
#define   RALINK_ESW_SGC_BP_MODE		GENMASK(19, 18)
#define   RALINK_ESW_SGC_DISMII_WAS_TX		GENMASK(17, 16)
#define   RALINK_ESW_SGC_BP_JAM_CNT		GENMASK(15, 12)
#define   RALINK_ESW_SGC_DIS_TX_BACKOFF		BIT(11)
#define   RALINK_ESW_SGC_ADDR_HASH_ALG		GENMASK(10, 9)
#define   RALINK_ESW_SGC_DIS_PKT_TX_ABORT	BIT(8)
#define   RALINK_ESW_SGC_PKT_MAX_LEN		GENMASK(7, 6)
#define   RALINK_ESW_SGC_BC_STORM_PROT		GENMASK(5, 4)
#define   RALINK_ESW_SGC_AGING_INTERVAL		GENMASK(3, 0)

#define RALINK_ESW_SGC2				0x00e4
#define   RALINK_ESW_SGC2_P6_RXFC_QUE_EN	BIT(31)
#define   RALINK_ESW_SGC2_P6_TXFC_WL_EN		BIT(30)
#define   RALINK_ESW_SGC2_LAN_PMAP		GENMASK(29, 24)
#define   RALINK_ESW_SGC2_SPECIAL_TAG		BIT(23)
#define   RALINK_ESW_SGC2_PORT6_ID		BIT(22)
#define   RALINK_ESW_SGC2_TX_CPU_TPID_BIT_MAP	GENMASK(22, 16)
#define   RALINK_ESW_SGC2_P6_TXFC_QUE_EN	BIT(12)
#define   RALINK_ESW_SGC2_CPU_TPID_EN		BIT(10)
#define   RALINK_ESW_SGC2_DOUBLE_TAG_EN		GENMASK(6, 0)

#define RALINK_ESW_SGC2_DOUBLE_TAG_EN_BIT(port) BIT(port)

#define RALINK_ESW_POC1				0x0094
#define   RALINK_ESW_POC1_DIS_IPMC2CPU		GENMASK(29, 23)
#define   RALINK_ESW_POC1_BLOCKING		GENMASK(22, 16)
#define   RALINK_ESW_POC1_BLOCKING_SHIFT	16
#define   RALINK_ESW_POC1_DIS_LRNING		GENMASK(14, 8)
#define   RALINK_ESW_POC1_DIS_LRNING_SHIFT	8
#define   RALINK_ESW_POC1_SA_SECURE_PORT	GENMASK(6, 0)

#define RALINK_ESW_POC1_BLOCKING_BIT(port) \
	BIT(RALINK_ESW_POC1_BLOCKING_SHIFT + (port))

#define RALINK_ESW_POC1_DIS_LRNING_BIT(port) \
	BIT(RALINK_ESW_POC1_DIS_LRNING_SHIFT + (port))

#define RALINK_ESW_POC2				0x0098
#define   RALINK_ESW_POC2_MLD2CPU_EN		BIT(25)
#define   RALINK_ESW_POC2_IPV6_MULT_RULE	GENMASK(24, 23)
#define   RALINK_ESW_POC2_DIS_UC_PAUSE		GENMASK(22, 16)
#define   RALINK_ESW_POC2_PER_VLAN_UNTAG_EN	BIT(15)
#define   RALINK_ESW_POC2_ENAGING		GENMASK(14, 8)
#define   RALINK_ESW_POC2_ENAGING_SHIFT		8
#define   RALINK_ESW_POC2_UNTAG_EN		GENMASK(6, 0)
#define   RALINK_ESW_POC2_UNTAG_EN_SHIFT	0

#define RALINK_ESW_POC2_ENAGING_BIT(port) \
	BIT(RALINK_ESW_POC2_ENAGING_SHIFT + (port))

#define RALINK_ESW_POC2_UNTAG_EN_BIT(port) \
	BIT(RALINK_ESW_POC2_UNTAG_EN_SHIFT + (port))

#define RALINK_ESW_P0PC				0x00e8
#define RALINK_ESW_P0TPC			0x0150
#define RALINK_ESW_PCRI				0x014c

#define   RALINK_ESW_PKT_CNT_GOOD		GENMASK(15, 0)
#define   RALINK_ESW_PKT_CNT_BAD		GENMASK(31, 16)

#define   RALINK_ESW_PCRI_GOOD_PKT_REC(port)	BIT(port)
#define   RALINK_ESW_PCRI_BADD_PKT_REC(port)	BIT((port) + 8)
#define   RALINK_ESW_PCRI_TXOK_PKT_REC(port)	BIT((port) + 16)
#define   RALINK_ESW_PCRI_TCOL_PKT_REC(port)	BIT((port) + 24)

/* HW LEDS */
#define RALINK_ESW_LED_LINK			0x0
#define RALINK_ESW_LED_100M			0x1
#define RALINK_ESW_LED_DUPLEX			0x2
#define RALINK_ESW_LED_ACTIVITY			0x3
#define RALINK_ESW_LED_COLLISION		0x4
#define RALINK_ESW_LED_LINK_ACTIVITY		0x5
#define RALINK_ESW_LED_DUPLEX_COLLISION		0x6
#define RALINK_ESW_LED_10M_ACTIVITY		0x7
#define RALINK_ESW_LED_100M_ACTIVITY		0x8
#define RALINK_ESW_LED_OFF			0x9
#define RALINK_ESW_LED_ON			0xa
#define RALINK_ESW_LED_BLINK			0xb

#define RALINK_ESW_PLED(_p)			(0x00a4 + ((_p) * 4))
#define RALINK_ESW_PLED_MODE			GENMASK(3, 0)

/* ATU / MAC table search & write */
#define RALINK_ESW_ATS				0x0084
#define   RALINK_ESW_ATS_SEARCH_NEXT_ADDR	BIT(1)
#define   RALINK_ESW_ATS_BEGIN_SEARCH_ADDR	BIT(0)

#define RALINK_ESW_ATS0				0x0088
#define   RALINK_ESW_ATS0_SEARCH_RDY		BIT(0)
#define   RALINK_ESW_ATS0_AT_TABLE_END		BIT(1)
#define   RALINK_ESW_ATS0_R_AGE_FIELD		GENMASK(6, 4)
#define   RALINK_ESW_ATS0_R_PORT_MAP		GENMASK(14, 8)
#define   RALINK_ESW_ATS0_R_VID			GENMASK(18, 15)
#define   RALINK_ESW_ATS0_R_MC_INGRESS		BIT(19)

#define RALINK_ESW_ATS1				0x008c
#define RALINK_ESW_ATS2				0x0090

#define RALINK_ESW_WMAD0			0x0094
#define   RALINK_ESW_WMAD0_W_MAC_DONE		BIT(0)
#define   RALINK_ESW_WMAD0_W_MAC_CMD		BIT(1)
#define   RALINK_ESW_WMAD0_W_AGE_FIELD		GENMASK(6, 4)
#define   RALINK_ESW_WMAD0_W_PORT_MAP		GENMASK(14, 8)
#define   RALINK_ESW_WMAD0_W_INDEX		GENMASK(18, 15)
#define   RALINK_ESW_WMAD0_W_MC_INGRESS		BIT(19)

#define RALINK_ESW_WMAD1			0x0098
#define RALINK_ESW_WMAD2			0x009c

/* ATU age encoding */
#define RALINK_ESW_ATU_AGE_INVALID		0
#define RALINK_ESW_ATU_AGE_STATIC		7

/* Packed VLAN tables */
#define RALINK_ESW_PVIDC_BASE			0x0040
#define RALINK_ESW_VLANI_BASE			0x0050
#define RALINK_ESW_VMSC_BASE			0x0070
#define RALINK_ESW_VUB_BASE			0x0100

#define RALINK_ESW_TBL_PER_REG_2		2
#define RALINK_ESW_TBL_PER_REG_4		4

#define RALINK_ESW_TBL_WID_VID			16 /* 12 bits used */
#define RALINK_ESW_TBL_WID_MSC			8  /* port bitmap */
#define RALINK_ESW_TBL_WID_UTG			8  /* untag bitmap */

/* Packed lane helper (idx selects lane 0/1 within a 32-bit register) */
static inline u32 ralink_esw_tbl_reg(u32 base, u16 idx, u16 per_reg)
{
	return base + (idx / per_reg) * 4;
}

static inline u32 ralink_esw_tbl_mask(u16 idx, u16 per_reg, u16 width)
{
	u16 shift = (idx % per_reg) * width;

	return GENMASK(width - 1, 0) << shift;
}

/* PVID: per port */
static inline u32 ralink_esw_pvidc_reg(unsigned int port)
{
	return ralink_esw_tbl_reg(RALINK_ESW_PVIDC_BASE, port,
					RALINK_ESW_TBL_PER_REG_2);
}
static inline u32 ralink_esw_pvidc_mask(unsigned int port)
{
	return ralink_esw_tbl_mask(port, RALINK_ESW_TBL_PER_REG_2,
					RALINK_ESW_TBL_WID_VID);
}

/* VLANI/VMSC/VUB: per VLAN table slot 0..15 */
static inline u32 ralink_esw_vlani_reg(unsigned int slot)
{
	return ralink_esw_tbl_reg(RALINK_ESW_VLANI_BASE, slot,
					RALINK_ESW_TBL_PER_REG_2);
}
static inline u32 ralink_esw_vlani_mask(unsigned int slot)
{
	return ralink_esw_tbl_mask(slot, RALINK_ESW_TBL_PER_REG_2,
					RALINK_ESW_TBL_WID_VID);
}

static inline u32 ralink_esw_vmsc_reg(unsigned int slot)
{
	return ralink_esw_tbl_reg(RALINK_ESW_VMSC_BASE, slot,
					RALINK_ESW_TBL_PER_REG_2);
}
static inline u32 ralink_esw_vmsc_mask(unsigned int slot)
{
	return ralink_esw_tbl_mask(slot, RALINK_ESW_TBL_PER_REG_2,
					RALINK_ESW_TBL_WID_MSC);
}

static inline u32 ralink_esw_vub_reg(unsigned int slot)
{
	return ralink_esw_tbl_reg(RALINK_ESW_VUB_BASE, slot,
					RALINK_ESW_TBL_PER_REG_2);
}
static inline u32 ralink_esw_vub_mask(unsigned int slot)
{
	return ralink_esw_tbl_mask(slot, RALINK_ESW_TBL_PER_REG_2,
					RALINK_ESW_TBL_WID_UTG);
}

#define RALINK_ESW_RL_MAX_TOKEN         0x3ff
#define RALINK_ESW_RL_MAX_THRESHOLD     0xffff

#define RALINK_ESW_P01_ING_CTRL         0x0120
#define RALINK_ESW_P0_ING_THRES         0x012c
#define RALINK_ESW_P01_EG_CTRL          0x0140
#define RALINK_ESW_INGRESS_CTRL(_s)         BIT((_s) + 14)
#define RALINK_ESW_INGRESS_MGMT_BYPASS(_s)  BIT((_s) + 13)
#define RALINK_ESW_INGRESS_FLOW_CTRL(_s)    BIT((_s) + 12)

#define RALINK_ESW_INGRESS_TICK(_s)         GENMASK((_s) + 11, (_s) + 10)
#define RALINK_ESW_INGRESS_TOKEN(_s)        GENMASK((_s) + 9, _s)

#define RALINK_ESW_INGRESS_FC_OFF_THRES     GENMASK(31, 16)
#define RALINK_ESW_INGRESS_FC_ON_THRES      GENMASK(15, 0)

#define RALINK_ESW_EGRESS_CTRL(_s)          BIT((_s) + 12)
#define RALINK_ESW_EGRESS_TICK(_s)          GENMASK((_s) + 11, (_s) + 10)
#define RALINK_ESW_EGRESS_TOKEN(_s)         GENMASK((_s) + 9, _s)

static const u32 ralink_esw_rl_tick_us[] = { 512, 128, 32, 8 };

static inline u32 ralink_esw_ing_ctrl_reg(unsigned int port)
{
	return RALINK_ESW_P01_ING_CTRL + (port / 2) * 4;
}

static inline u32 ralink_esw_eg_ctrl_reg(unsigned int port)
{
	return RALINK_ESW_P01_EG_CTRL + (port / 2) * 4;
}

static inline u32 ralink_esw_ing_thres_reg(unsigned int port)
{
	return RALINK_ESW_P0_ING_THRES + port * 4;
}

static inline u16 ralink_esw_rl_shift(unsigned int port)
{
	return (port & 1) ? 16 : 0;
}

struct ralink_esw_port_stats {
	u64				rx_good_pkts;
	u64				rx_bad_pkts;
	u64				tx_good_pkts;
	u64				tx_bad_pkts;
};

struct ralink_esw_atu_entry {
	u8				mac[ETH_ALEN];
	u8				port_mask;
	u8				vlan_idx;
	u8				age_field;
	u16				vid;
	bool				is_static;
	bool				is_multicast;
};

struct ralink_esw_port {
	bool				vlan_filtering;
	bool				learning;

	u16				pvid_tag_8021q;
	bool				pvid_tag_8021q_configured;

	u16				pvid_vlan_filtering;
	bool				pvid_vlan_filtering_configured;
};

struct ralink_esw {
	struct device			*dev;
	void __iomem			*base;

	struct clk			*clk;
	struct reset_control		*rst_esw;
	struct reset_control		*rst_ephy;
	struct regmap			*sdm;

	/* MDIO */
	struct mutex			mdio_lock;
	struct mii_bus			*mdio_bus;

	u32				link_state;

	struct dsa_switch		*ds;

	DECLARE_BITMAP(vlan_slot, RALINK_ESW_NUM_VLANS);
	u16				vlan_vid[RALINK_ESW_NUM_VLANS];
	u8				vlan_member[RALINK_ESW_NUM_VLANS];
	u8				vlan_untag[RALINK_ESW_NUM_VLANS];

	struct ralink_esw_port		ports[RALINK_ESW_NUM_PORTS];
	int				cpu_port;

	struct mutex			fdb_mutex;

	struct delayed_work		stats_work;
	struct ralink_esw_port_stats	stats[RALINK_ESW_NUM_PORTS];
	struct mutex			reg_mutex;
	bool				stats_running;
};

#ifdef CONFIG_LEDS_CLASS
int ralink_esw_leds_probe(struct ralink_esw *esw);
#else
static inline int ralink_esw_leds_probe(struct ralink_esw *esw) { return 0; }
#endif

void ralink_esw_rmw(struct ralink_esw *esw, u32 reg, u32 mask, u32 set);

#endif /* _RALINK_ESW_DSA_H_ */
