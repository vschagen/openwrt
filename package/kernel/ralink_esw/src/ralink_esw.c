// SPDX-License-Identifier: GPL-2.0
/*
 * DSA switch driver for the classic Ralink/MediaTek embedded switch (ESW)
 * found in RT5350/MT76x8 class SoCs.
 *
 */

#include <linux/clk.h>
#include <linux/dsa/8021q.h>
#include <linux/if_bridge.h>
#include <linux/math64.h>
#include <linux/mfd/syscon.h>
#include <linux/of_mdio.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <net/dsa.h>
#include <net/pkt_cls.h>

#include "ralink_esw.h"

static inline u32 ralink_esw_r32(struct ralink_esw *esw, u32 reg)
{
	return readl_relaxed(esw->base + reg);
}

static inline void ralink_esw_w32(struct ralink_esw *esw, u32 reg, u32 val)
{
	writel_relaxed(val, esw->base + reg);
}

void ralink_esw_rmw(struct ralink_esw *esw, u32 reg, u32 mask, u32 set)
{
	u32 val = ralink_esw_r32(esw, reg);

	val &= ~mask;
	val |= (set & mask);

	ralink_esw_w32(esw, val, reg);
}

/*
 * PCR1.RD_RDY and PCR1.WT_DONE are read-clear completion bits.
 * Read PCR1 before starting a transaction to drop any stale completion
 * state, then read it again after completion to fetch data / acknowledge
 * completion.
 */
static inline void ralink_esw_mdio_ack(struct ralink_esw *esw)
{
	ralink_esw_r32(esw, RALINK_ESW_PCR1);
}

static int ralink_esw_mdio_wait(struct ralink_esw *esw, u32 mask)
{
	u32 val;

	return readl_poll_timeout(esw->base + RALINK_ESW_PCR1, val,
				val & mask, 1,
				RALINK_ESW_MDIO_TIMEOUT_US);
}

static int ralink_esw_phy_read(struct ralink_esw *esw, int phy, int reg, u16 *val)
{
	u32 pcr1;
	int ret;

	mutex_lock(&esw->mdio_lock);

	ralink_esw_mdio_ack(esw);

	ralink_esw_w32(esw, RALINK_ESW_PCR0,
		RALINK_ESW_PCR0_RD_PHY_CMD |
			FIELD_PREP(RALINK_ESW_PCR0_PHY_REG, reg) |
			FIELD_PREP(RALINK_ESW_PCR0_PHY_ADDR, phy));

	ret = ralink_esw_mdio_wait(esw, RALINK_ESW_PCR1_RD_RDY);
	if (ret) {
		dev_err(esw->dev, "MDIO read timeout: phy=%d reg=%d\n",
		phy, reg);
		goto out;
	}

	pcr1 = ralink_esw_r32(esw, RALINK_ESW_PCR1);
	*val = FIELD_GET(RALINK_ESW_PCR1_RD_DATA, pcr1);

out:
	mutex_unlock(&esw->mdio_lock);

	return ret;
}

static int ralink_esw_phy_write(struct ralink_esw *esw, int phy, int reg, u16 val)
{
	int ret;

	mutex_lock(&esw->mdio_lock);

	ralink_esw_mdio_ack(esw);

	ralink_esw_w32(esw, RALINK_ESW_PCR0,
			RALINK_ESW_PCR0_WT_PHY_CMD |
			FIELD_PREP(RALINK_ESW_PCR0_WT_DATA, val) |
			FIELD_PREP(RALINK_ESW_PCR0_PHY_REG, reg) |
			FIELD_PREP(RALINK_ESW_PCR0_PHY_ADDR, phy));

	ret = ralink_esw_mdio_wait(esw, RALINK_ESW_PCR1_WT_DONE);
	if (ret) {
		dev_err(esw->dev, "MDIO write timeout: phy=%d reg=%d\n",
		phy, reg);
	goto out;
	}

	ralink_esw_mdio_ack(esw);

out:
	mutex_unlock(&esw->mdio_lock);

	return ret;
}

static int ralink_esw_mdio_bus_read(struct mii_bus *bus, int addr, int regnum)
{
	struct ralink_esw *esw = bus->priv;
	u16 val;
	int ret;

	ret = ralink_esw_phy_read(esw, addr, regnum, &val);
	if (ret)
		return ret;

	return val;
}

static int ralink_esw_mdio_bus_write(struct mii_bus *bus, int addr,
					int regnum, u16 val)
{
	struct ralink_esw *esw = bus->priv;

	return ralink_esw_phy_write(esw, addr, regnum, val);
}

static int ralink_esw_mdio_register(struct ralink_esw *esw)
{
	struct device_node *mdio_np;
	struct mii_bus *bus;
	int ret;

	mdio_np = of_get_child_by_name(esw->dev->of_node, "mdio");
	if (!mdio_np)
		return 0;

	bus = devm_mdiobus_alloc(esw->dev);
	if (!bus) {
		of_node_put(mdio_np);
		return -ENOMEM;
	}

	bus->name = "ralink-esw-mdio";
	bus->read = ralink_esw_mdio_bus_read;
	bus->write = ralink_esw_mdio_bus_write;
	bus->parent = esw->dev;
	bus->priv = esw;

	strscpy(bus->id, dev_name(esw->dev), MII_BUS_ID_SIZE);

	ret = devm_of_mdiobus_register(esw->dev, bus, mdio_np);
	of_node_put(mdio_np);
	if (ret)
		return dev_err_probe(esw->dev, ret,
				"failed to register MDIO bus\n");

	esw->mdio_bus = bus;

	return 0;
}

static inline u32 ralink_esw_port_bit(unsigned int shift, unsigned int port)
{
	return BIT(shift + port);
}

static inline void
ralink_esw_set_port_bit(struct ralink_esw *esw, u32 reg, unsigned int shift,
			unsigned int port, bool enable)
{
	u32 mask = ralink_esw_port_bit(shift, port);

	ralink_esw_rmw(esw, reg, mask, enable ? mask : 0);
}

static inline void
ralink_esw_fpa_set_force_mode(struct ralink_esw *esw, unsigned int port, bool en)
{
	ralink_esw_set_port_bit(esw, RALINK_ESW_FPA,
				RALINK_ESW_FPA_FORCE_MODE_SHIFT,
				port, en);
}

static inline void
ralink_esw_fpa1_set_force_mode(struct ralink_esw *esw, unsigned int port,
			       bool enable)
{
	u32 bit = (port == 5) ? RALINK_ESW_FPA1_FORCE_EN0
			      : RALINK_ESW_FPA1_FORCE_EN1;

	ralink_esw_rmw(esw, RALINK_ESW_FPA1, bit, enable ? bit : 0);
}


static inline void
ralink_esw_fpa_set_link(struct ralink_esw *esw, unsigned int port, bool up)
{
	ralink_esw_set_port_bit(esw, RALINK_ESW_FPA,
				RALINK_ESW_FPA_FORCE_LNK_SHIFT,
				port, up);
}

static inline void
ralink_esw_fpa1_set_link(struct ralink_esw *esw, unsigned int port, bool up)
{
	u32 bit = (port == 5) ? RALINK_ESW_FPA1_FORCE_LNK0
			      : RALINK_ESW_FPA1_FORCE_LNK1;

	ralink_esw_rmw(esw, RALINK_ESW_FPA1, bit, up ? bit : 0);
}


static inline void
ralink_esw_fpa_set_speed(struct ralink_esw *esw, unsigned int port, int speed)
{
	ralink_esw_set_port_bit(esw, RALINK_ESW_FPA,
				RALINK_ESW_FPA_FORCE_SPD_SHIFT,
				port, speed == SPEED_100);
}

static inline void
ralink_esw_fpa1_set_speed(struct ralink_esw *esw, unsigned int port, int speed)
{
	u32 mask  = (port == 5) ? RALINK_ESW_FPA1_FORCE_SPD0
			       : RALINK_ESW_FPA1_FORCE_SPD1;
	u32 shift = (port == 5) ? RALINK_ESW_FPA1_FORCE_SPD0_SHIFT
			       : RALINK_ESW_FPA1_FORCE_SPD1_SHIFT;
	u32 val;

	switch (speed) {
	case SPEED_1000:
		val = 2;
		break;
	case SPEED_100:
		val = 1;
		break;
	default:
		val = 0;
		break;
	}

	ralink_esw_rmw(esw, RALINK_ESW_FPA1, mask, (val << shift) & mask);
}

static inline void
ralink_esw_fpa_set_duplex(struct ralink_esw *esw, unsigned int port, bool full)
{
	ralink_esw_set_port_bit(esw, RALINK_ESW_FPA,
				RALINK_ESW_FPA_FORCE_DPX_SHIFT,
				port, full);
}

static inline void
ralink_esw_fpa1_set_duplex(struct ralink_esw *esw, unsigned int port,
			   bool full)
{
	u32 bit = (port == 5) ? RALINK_ESW_FPA1_FORCE_DPX0
			      : RALINK_ESW_FPA1_FORCE_DPX1;

	ralink_esw_rmw(esw, RALINK_ESW_FPA1, bit, full ? bit : 0);
}

static inline void
ralink_esw_fpa_set_pause(struct ralink_esw *esw, unsigned int port, bool en)
{
	ralink_esw_set_port_bit(esw, RALINK_ESW_FPA,
				RALINK_ESW_FPA_FORCE_XFC_SHIFT,
				port, en);
}

static inline void
ralink_esw_fpa1_set_pause(struct ralink_esw *esw, unsigned int port,
			  bool tx_pause, bool rx_pause)
{
	u32 mask  = (port == 5) ? RALINK_ESW_FPA1_FORCE_XFC0
			       : RALINK_ESW_FPA1_FORCE_XFC1;
	u32 shift = (port == 5) ? RALINK_ESW_FPA1_FORCE_XFC0_SHIFT
			       : RALINK_ESW_FPA1_FORCE_XFC1_SHIFT;
	u32 val = (tx_pause ? 0x2 : 0) | (rx_pause ? 0x1 : 0);

	ralink_esw_rmw(esw, RALINK_ESW_FPA1, mask, (val << shift) & mask);
}

static void ralink_esw_port_set_force_mode(struct ralink_esw *esw, int port,
					   bool enable)
{
	if (port <= 4)
		ralink_esw_fpa_set_force_mode(esw, port, enable);
	else
		ralink_esw_fpa1_set_force_mode(esw, port, enable);
}

static void ralink_esw_port_set_link(struct ralink_esw *esw, int port, bool up)
{
	if (port <= 4)
		ralink_esw_fpa_set_link(esw, port, up);
	else
		ralink_esw_fpa1_set_link(esw, port, up);
}

static void ralink_esw_port_set_speed(struct ralink_esw *esw, int port, int speed)
{
	if (port <= 4)
		ralink_esw_fpa_set_speed(esw, port, speed);
	else
		ralink_esw_fpa1_set_speed(esw, port, speed);
}

static void ralink_esw_port_set_duplex(struct ralink_esw *esw, int port, bool full)
{
	if (port <= 4)
		ralink_esw_fpa_set_duplex(esw, port, full);
	else
		ralink_esw_fpa1_set_duplex(esw, port, full);
}

static void ralink_esw_port_set_pause(struct ralink_esw *esw, int port,
				      bool tx_pause, bool rx_pause)
{
	if (port <= 4)
		ralink_esw_fpa_set_pause(esw, port, tx_pause && rx_pause);
	else
		ralink_esw_fpa1_set_pause(esw, port, tx_pause, rx_pause);
}

static void ralink_esw_phylink_get_caps(struct dsa_switch *ds, int port,
					struct phylink_config *config)
{
	switch (port) {
	case 0 ... 4:
		config->mac_capabilities = MAC_10 | MAC_100 | MAC_SYM_PAUSE;
		break;
	case 6:
		config->mac_capabilities = MAC_10 | MAC_100 | MAC_1000FD |
					   MAC_SYM_PAUSE | MAC_ASYM_PAUSE;
		break;
	default:
		config->mac_capabilities = 0;
		break;
	}
}

static void ralink_esw_mac_config(struct phylink_config *config,
				  unsigned int mode,
				  const struct phylink_link_state *state)
{
	/* Nothing to program until link-up/link-down. */
}

static void ralink_esw_mac_link_down(struct phylink_config *config,
				     unsigned int mode,
				     phy_interface_t interface)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct ralink_esw *esw = dp->ds->priv;

	ralink_esw_port_set_force_mode(esw, dp->index, true);
	ralink_esw_port_set_link(esw, dp->index, false);
}

static void ralink_esw_mac_link_up(struct phylink_config *config,
				   struct phy_device *phydev,
				   unsigned int mode,
				   phy_interface_t interface,
				   int speed, int duplex,
				   bool tx_pause, bool rx_pause)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);
	struct ralink_esw *esw = dp->ds->priv;

	ralink_esw_port_set_force_mode(esw, dp->index, true);
	ralink_esw_port_set_speed(esw, dp->index, speed);
	ralink_esw_port_set_duplex(esw, dp->index, duplex == DUPLEX_FULL);
	ralink_esw_port_set_pause(esw, dp->index, tx_pause, rx_pause);
	ralink_esw_port_set_link(esw, dp->index, true);
}

static const struct phylink_mac_ops ralink_esw_phylink_mac_ops = {
	.mac_config	= ralink_esw_mac_config,
	.mac_link_down	= ralink_esw_mac_link_down,
	.mac_link_up	= ralink_esw_mac_link_up,
};

static const char ralink_esw_stats_strings[][ETH_GSTRING_LEN] = {
	"rx_good_pkts",
	"rx_bad_pkts",
	"tx_good_pkts",
	"tx_bad_pkts",
};

static void ralink_esw_stats_update(struct ralink_esw *esw)
{
	struct dsa_switch *ds = esw->ds;
	u32 recycle = 0;
	int port;

	mutex_lock(&esw->reg_mutex);
	for (port = 0; port < ds->num_ports; port++) {
		u32 rx, tx;

		if (!dsa_is_user_port(ds, port))
			continue;

		rx = ralink_esw_r32(esw, RALINK_ESW_P0PC + port * 4);
		tx = ralink_esw_r32(esw, RALINK_ESW_P0TPC + port * 4);

		esw->stats[port].rx_good_pkts +=
		FIELD_GET(RALINK_ESW_PKT_CNT_GOOD, rx);
		esw->stats[port].rx_bad_pkts +=
			FIELD_GET(RALINK_ESW_PKT_CNT_BAD, rx);

		esw->stats[port].tx_good_pkts +=
			FIELD_GET(RALINK_ESW_PKT_CNT_GOOD, tx);
		esw->stats[port].tx_bad_pkts +=
			FIELD_GET(RALINK_ESW_PKT_CNT_BAD, tx);

		recycle |= RALINK_ESW_PCRI_GOOD_PKT_REC(port);
		recycle |= RALINK_ESW_PCRI_BADD_PKT_REC(port);
		recycle |= RALINK_ESW_PCRI_TXOK_PKT_REC(port);
		recycle |= RALINK_ESW_PCRI_TCOL_PKT_REC(port);
	}

	ralink_esw_w32(esw, RALINK_ESW_PCRI, recycle);

	mutex_unlock(&esw->reg_mutex);
}

static void ralink_esw_stats_work(struct work_struct *work)
{
	struct ralink_esw *esw;

	esw = container_of(to_delayed_work(work), struct ralink_esw,
			stats_work);

	ralink_esw_stats_update(esw);
	schedule_delayed_work(&esw->stats_work, RALINK_ESW_STATS_POLL_INTERVAL);
}

static void ralink_esw_stats_init(struct ralink_esw *esw)
{
	INIT_DELAYED_WORK(&esw->stats_work, ralink_esw_stats_work);
	schedule_delayed_work(&esw->stats_work, RALINK_ESW_STATS_POLL_INTERVAL);
}

static void ralink_esw_stats_deinit(struct ralink_esw *esw)
{
	cancel_delayed_work_sync(&esw->stats_work);
}

static void ralink_esw_get_strings(struct dsa_switch *ds, int port,
					u32 stringset, u8 *data)
{
	if (stringset != ETH_SS_STATS)
		return;

	memcpy(data, ralink_esw_stats_strings,
		sizeof(ralink_esw_stats_strings));
}

static int ralink_esw_get_sset_count(struct dsa_switch *ds, int port,
					int sset)
{
	if (sset != ETH_SS_STATS)
		return 0;

	return ARRAY_SIZE(ralink_esw_stats_strings);
}

static void ralink_esw_get_ethtool_stats(struct dsa_switch *ds, int port,
					u64 *data)
{
	struct ralink_esw *esw = ds->priv;

	mutex_lock(&esw->reg_mutex);

	data[0] = esw->stats[port].rx_good_pkts;
	data[1] = esw->stats[port].rx_bad_pkts;
	data[2] = esw->stats[port].tx_good_pkts;
	data[3] = esw->stats[port].tx_bad_pkts;

	mutex_unlock(&esw->reg_mutex);
}

static inline void ralink_esw_set_field(struct ralink_esw *esw, u32 base,
					u16 idx, u16 width, u16 per_reg,
					u32 val)
{
	u32 reg = ralink_esw_tbl_reg(base, idx, per_reg);
	u16 shift = (idx % per_reg) * width;
	u32 mask = GENMASK(width - 1, 0) << shift;
	u32 set = (val << shift) & mask;

	ralink_esw_rmw(esw, reg, mask, set);
}

static inline u32 ralink_esw_get_field(struct ralink_esw *esw, u32 base,
				       u16 idx, u16 width, u16 per_reg)
{
	u32 reg = ralink_esw_tbl_reg(base, idx, per_reg);
	u16 shift = (idx % per_reg) * width;
	u32 mask = GENMASK(width - 1, 0) << shift;

	return (ralink_esw_r32(esw, reg) & mask) >> shift;
}

/* semantic table helpers */
static inline void ralink_esw_set_pvid(struct ralink_esw *esw,
				       unsigned int port, u16 vid)
{
	ralink_esw_set_field(esw, RALINK_ESW_PVIDC_BASE, port,
			     RALINK_ESW_TBL_WID_VID,
			     RALINK_ESW_TBL_PER_REG_2, vid);
}

static inline void ralink_esw_set_vlan_vid(struct ralink_esw *esw,
					   unsigned int slot, u16 vid)
{
	ralink_esw_set_field(esw, RALINK_ESW_VLANI_BASE, slot,
			     RALINK_ESW_TBL_WID_VID,
			     RALINK_ESW_TBL_PER_REG_2, vid);
}

static inline void ralink_esw_set_vlan_members(struct ralink_esw *esw,
					       unsigned int slot, u8 members)
{
	ralink_esw_set_field(esw, RALINK_ESW_VMSC_BASE, slot,
			     RALINK_ESW_TBL_WID_MSC,
			     RALINK_ESW_TBL_PER_REG_4, members);
}

static inline void ralink_esw_set_vlan_untag(struct ralink_esw *esw,
					     unsigned int slot, u8 untag)
{
	ralink_esw_set_field(esw, RALINK_ESW_VUB_BASE, slot,
			     RALINK_ESW_TBL_WID_UTG,
			     RALINK_ESW_TBL_PER_REG_4, untag);
}

static void ralink_esw_vlan_write(struct ralink_esw *esw, unsigned int slot)
{
	ralink_esw_set_vlan_vid(esw, slot, esw->vlan_vid[slot]);
	ralink_esw_set_vlan_members(esw, slot, esw->vlan_member[slot]);
	ralink_esw_set_vlan_untag(esw, slot, esw->vlan_untag[slot]);
}

static int ralink_esw_find_vlan_slot(struct ralink_esw *esw, u16 vid)
{
	int i;

	for_each_set_bit(i, esw->vlan_slot, RALINK_ESW_NUM_VLANS) {
		if (esw->vlan_vid[i] == vid)
			return i;
	}

	return -ENOENT;
}

static int ralink_esw_alloc_vlan_slot(struct ralink_esw *esw, u16 vid)
{
	int i;

	i = ralink_esw_find_vlan_slot(esw, vid);
	if (i >= 0)
		return i;

	i = find_first_zero_bit(esw->vlan_slot, RALINK_ESW_NUM_VLANS);
	if (i >= RALINK_ESW_NUM_VLANS)
		return -ENOSPC;

	set_bit(i, esw->vlan_slot);

	esw->vlan_vid[i] = vid;
	esw->vlan_member[i] = 0;
	esw->vlan_untag[i] = 0;

	ralink_esw_vlan_write(esw, i);

	return i;
}

static void ralink_esw_free_vlan_slot(struct ralink_esw *esw, int i)
{
	clear_bit(i, esw->vlan_slot);

	esw->vlan_vid[i] = RALINK_ESW_VID_NONE;
	esw->vlan_member[i] = 0;
	esw->vlan_untag[i] = 0;

	ralink_esw_vlan_write(esw, i);
}

static inline u16 ralink_esw_vlan_from_idx(struct ralink_esw *esw,
					   unsigned int idx)
{
	if (idx >= RALINK_ESW_NUM_VLANS)
		return RALINK_ESW_VID_NONE;

	if (!test_bit(idx, esw->vlan_slot))
		return RALINK_ESW_VID_NONE;

	return esw->vlan_vid[idx];
}

static int ralink_esw_vlan_to_idx(struct ralink_esw *esw, u16 vid)
{
	return ralink_esw_find_vlan_slot(esw, vid);
}

static int ralink_esw_port_commit_pvid(struct ralink_esw *esw, int port)
{
	struct ralink_esw_port *p = &esw->ports[port];
	u16 vid = 0;
	bool valid = false;

	vid = p->pvid_tag_8021q;
	valid = p->pvid_tag_8021q_configured;

	if (p->vlan_filtering) {
		vid = p->pvid_vlan_filtering;
		valid = p->pvid_vlan_filtering_configured;
	}

	if (!valid)
		vid = 0;

	ralink_esw_set_pvid(esw, port, vid);

	return 0;
}

static int ralink_esw_port_vlan_filtering(struct dsa_switch *ds, int port,
					  bool vlan_filtering,
					  struct netlink_ext_ack *extack)
{
	struct ralink_esw *esw = ds->priv;
	u32 mask, set;

	if (dsa_is_cpu_port(ds, port))
		vlan_filtering = true;

	mask = RALINK_ESW_PFC1_EN_VLAN_BIT(port);
	set = vlan_filtering ? mask : 0;
	ralink_esw_rmw(esw, RALINK_ESW_PFC1, mask, set);

	mask = RALINK_ESW_SGC2_DOUBLE_TAG_EN_BIT(port);
	set = vlan_filtering ? 0 : mask;
	ralink_esw_rmw(esw, RALINK_ESW_SGC2, mask, set);

	esw->ports[port].vlan_filtering = vlan_filtering;

	return ralink_esw_port_commit_pvid(esw, port);
}

static int ralink_esw_port_vlan_add(struct dsa_switch *ds, int port,
				    const struct switchdev_obj_port_vlan *vlan,
				    struct netlink_ext_ack *extack)
{
	struct ralink_esw *esw = ds->priv;
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	u16 vid = vlan->vid;
	int slot, err;

	if (vid_is_dsa_8021q(vid)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Range 3072-4095 reserved for dsa_8021q operation");
		return -EBUSY;
	}

	slot = ralink_esw_alloc_vlan_slot(esw, vid);
	if (slot < 0)
		return slot;

	esw->vlan_member[slot] |= BIT(port);
	/* CPU port must always remain tagged */
	untagged = untagged && port != esw->cpu_port;

	if (untagged)
		esw->vlan_untag[slot] |= BIT(port);
	else
		esw->vlan_untag[slot] &= ~BIT(port);

	ralink_esw_vlan_write(esw, slot);

	if (pvid) {
		esw->ports[port].pvid_vlan_filtering = vid;
		esw->ports[port].pvid_vlan_filtering_configured = true;

		err = ralink_esw_port_commit_pvid(esw, port);
		if (err)
			return err;
	}

	return 0;
}

static int ralink_esw_port_vlan_del(struct dsa_switch *ds, int port,
				    const struct switchdev_obj_port_vlan *vlan)
{
	struct ralink_esw *esw = ds->priv;
	u16 vid = vlan->vid;
	int slot;

	slot = ralink_esw_find_vlan_slot(esw, vid);
	if (slot < 0)
		return 0;

	esw->vlan_member[slot] &= ~BIT(port);
	esw->vlan_untag[slot] &= ~BIT(port);

	ralink_esw_vlan_write(esw, slot);

	if (!esw->vlan_member[slot])
		ralink_esw_free_vlan_slot(esw, slot);

	return 0;
}

static int ralink_esw_tag_8021q_vlan_add(struct dsa_switch *ds, int port,
					 u16 vid, u16 flags)
{
	struct ralink_esw *esw = ds->priv;
	bool untagged = flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool pvid = flags & BRIDGE_VLAN_INFO_PVID;
	int slot, err;

	slot = ralink_esw_alloc_vlan_slot(esw, vid);
	if (slot < 0)
		return slot;

	esw->vlan_member[slot] |= BIT(port) | BIT(esw->cpu_port);

	if (untagged)
		esw->vlan_untag[slot] |= BIT(port);
	else
		esw->vlan_untag[slot] &= ~BIT(port);

	/* CPU port must always remain tagged */
	esw->vlan_untag[slot] &= ~BIT(esw->cpu_port);

	ralink_esw_vlan_write(esw, slot);

	if (pvid) {
		esw->ports[port].pvid_tag_8021q = vid;
		esw->ports[port].pvid_tag_8021q_configured = true;

		err = ralink_esw_port_commit_pvid(esw, port);
		if (err)
			return err;
	}

	return 0;
}

static int ralink_esw_tag_8021q_vlan_del(struct dsa_switch *ds, int port, u16 vid)
{
	struct ralink_esw *esw = ds->priv;
	const struct dsa_port *dp = dsa_to_port(ds, port);
	int slot, err;

	if (vid == dsa_tag_8021q_standalone_vid(dp))
		return 0;

	slot = ralink_esw_find_vlan_slot(esw, vid);
	if (slot < 0)
		return 0;

	esw->vlan_member[slot] &= ~BIT(port);
	esw->vlan_untag[slot] &= ~BIT(port);

	if (!(esw->vlan_member[slot] & ~BIT(esw->cpu_port)))
		ralink_esw_free_vlan_slot(esw, slot);
	else
		ralink_esw_vlan_write(esw, slot);

	if (esw->ports[port].pvid_tag_8021q_configured &&
	    esw->ports[port].pvid_tag_8021q == vid) {
		esw->ports[port].pvid_tag_8021q_configured = false;
		esw->ports[port].pvid_tag_8021q = 0;

		err = ralink_esw_port_commit_pvid(esw, port);
		if (err)
			return err;
	}

	return 0;
}


static int ralink_esw_atu_wait_ready(struct ralink_esw *esw)
{
	u32 val;

	return readl_poll_timeout(esw->base + RALINK_ESW_ATS0, val,
				  val & RALINK_ESW_ATS0_SEARCH_RDY,
				  1, RALINK_ESW_ATU_TIMEOUT_US);
}

static int ralink_esw_atu_wait_write_done(struct ralink_esw *esw)
{
	u32 val;

	return readl_poll_timeout(esw->base + RALINK_ESW_WMAD0, val,
				  val & RALINK_ESW_WMAD0_W_MAC_DONE,
				  1, RALINK_ESW_ATU_TIMEOUT_US);
}

static void ralink_esw_atu_mac_from_regs(u32 ats1, u32 ats2, u8 *mac)
{
	/* ATS1[15:0] = MAC[15:0], ATS2[31:0] = MAC[47:16] */
	mac[0] = (ats1 >> 8) & 0xff;
	mac[1] = ats1 & 0xff;
	mac[2] = (ats2 >> 24) & 0xff;
	mac[3] = (ats2 >> 16) & 0xff;
	mac[4] = (ats2 >> 8) & 0xff;
	mac[5] = ats2 & 0xff;
}

static void ralink_esw_atu_mac_to_regs(const u8 *mac, u32 *wmad1, u32 *wmad2)
{
	*wmad1 = (mac[0] << 8) | mac[1];
	*wmad2 = (mac[2] << 24) | (mac[3] << 16) |
		 (mac[4] << 8) | mac[5];
}

static int ralink_esw_atu_cmd(struct ralink_esw *esw, bool first)
{
	u32 cmd = first ? RALINK_ESW_ATS_BEGIN_SEARCH_ADDR :
			  RALINK_ESW_ATS_SEARCH_NEXT_ADDR;

	ralink_esw_w32(esw, RALINK_ESW_ATS, cmd);

	return ralink_esw_atu_wait_ready(esw);
}

/*
 * Returns:
 *   < 0 on error
 *   0 if entry is invalid and should be skipped
 *   1 if a valid entry was parsed into @ent
 */
static int ralink_esw_atu_read_entry(struct ralink_esw *esw,
				     struct ralink_esw_atu_entry *ent,
				     bool first, bool *end)
{
	u32 ats0, ats1, ats2;
	u8 vlan_idx;

	if (ralink_esw_atu_cmd(esw, first))
		return -ETIMEDOUT;

	/*
	 * SEARCH_RDY is read-clear, so read ATS0 once and keep it.
	 * ATS1/ATS2 can then be read for the MAC payload.
	 */
	ats0 = ralink_esw_r32(esw, RALINK_ESW_ATS0);
	ats1 = ralink_esw_r32(esw, RALINK_ESW_ATS1);
	ats2 = ralink_esw_r32(esw, RALINK_ESW_ATS2);

	*end = !!(ats0 & RALINK_ESW_ATS0_AT_TABLE_END);

	ent->age_field = FIELD_GET(RALINK_ESW_ATS0_R_AGE_FIELD, ats0);
	if (!ent->age_field)
		return 0;

	ralink_esw_atu_mac_from_regs(ats1, ats2, ent->mac);

	ent->port_mask = FIELD_GET(RALINK_ESW_ATS0_R_PORT_MAP, ats0);
	vlan_idx = FIELD_GET(RALINK_ESW_ATS0_R_VID, ats0);
	ent->vlan_idx = vlan_idx;
	ent->vid = ralink_esw_vlan_from_idx(esw, vlan_idx);
	ent->is_multicast = !!(ats0 & RALINK_ESW_ATS0_R_MC_INGRESS);
	/* age_field 7 means static entry */
	ent->is_static = ent->age_field == 7;

	return 1;
}

static int ralink_esw_atu_find(struct ralink_esw *esw, const u8 *mac, u16 vid,
			       bool is_multicast,
			       struct ralink_esw_atu_entry *match)
{
	struct ralink_esw_atu_entry ent;
	bool first = true, end = false;
	int ret;

	while (!end) {
		ret = ralink_esw_atu_read_entry(esw, &ent, first, &end);
		first = false;
		if (ret < 0)
			return ret;
		if (!ret)
			continue;

		if (ent.vid != vid)
			continue;
		if (ent.is_multicast != is_multicast)
			continue;
		if (!ether_addr_equal(ent.mac, mac))
			continue;

		*match = ent;
		return 0;
	}

	return -ENOENT;
}

/*
 * delete entry: age_field = RALINK_ESW_ATU_AGE_INVALID, port_mask = 0
 * static entry: age_field = RALINK_ESW_ATU_AGE_STATIC
 */
static int ralink_esw_atu_write(struct ralink_esw *esw, const u8 *mac, u16 vid,
				u8 port_mask, u8 age_field,
				bool is_multicast)
{
	u32 wmad0, wmad1, wmad2;
	int vlan_idx, ret;

	vlan_idx = ralink_esw_vlan_to_idx(esw, vid);
	if (vlan_idx < 0)
		return vlan_idx;

	ralink_esw_atu_mac_to_regs(mac, &wmad1, &wmad2);

	wmad0 = FIELD_PREP(RALINK_ESW_WMAD0_W_PORT_MAP, port_mask) |
		FIELD_PREP(RALINK_ESW_WMAD0_W_INDEX, vlan_idx) |
		FIELD_PREP(RALINK_ESW_WMAD0_W_AGE_FIELD, age_field);

	if (is_multicast)
		wmad0 |= RALINK_ESW_WMAD0_W_MC_INGRESS;

	ralink_esw_w32(esw, RALINK_ESW_WMAD1, wmad1);
	ralink_esw_w32(esw, RALINK_ESW_WMAD2, wmad2);
	ralink_esw_w32(esw, RALINK_ESW_WMAD0,
		       wmad0 | RALINK_ESW_WMAD0_W_MAC_CMD);

	ret = ralink_esw_atu_wait_write_done(esw);
	if (ret)
		return ret;

	/* W_MAC_DONE is read-clear */
	ralink_esw_r32(esw, RALINK_ESW_WMAD0);

	return 0;
}

static int ralink_esw_port_fdb_dump(struct dsa_switch *ds, int port,
				    dsa_fdb_dump_cb_t *cb, void *data)
{
	struct ralink_esw *esw = ds->priv;
	struct ralink_esw_atu_entry ent;
	bool first = true, end = false;
	int ret;

	mutex_lock(&esw->fdb_mutex);

	while (!end) {
		ret = ralink_esw_atu_read_entry(esw, &ent, first, &end);
		first = false;
		if (ret < 0)
			goto out;
		if (!ret)
			continue;

		if (ent.is_multicast)
			continue;
		if (!(ent.port_mask & BIT(port)))
			continue;

		/* Hide private dsa_8021q VLANs from userspace */
		if (vid_is_dsa_8021q(ent.vid))
			ent.vid = 0;

		ret = cb(ent.mac, ent.vid, ent.is_static, data);
		if (ret)
			goto out;
	}

	ret = 0;

out:
	mutex_unlock(&esw->fdb_mutex);
	return ret;
}

static int ralink_esw_db_vid(struct dsa_db db)
{
	switch (db.type) {
	case DSA_DB_PORT:
		return dsa_tag_8021q_standalone_vid(db.dp);
	case DSA_DB_BRIDGE:
		return dsa_tag_8021q_bridge_vid(db.bridge.num);
	default:
		return -EOPNOTSUPP;
	}
}

static int ralink_esw_port_fdb_add(struct dsa_switch *ds, int port,
				   const unsigned char *addr, u16 vid,
				   struct dsa_db db)
{
	struct ralink_esw *esw = ds->priv;
	int ret, fdb_vid = vid;

	if (!fdb_vid)
		fdb_vid = ralink_esw_db_vid(db);

	if (fdb_vid < 0)
		return fdb_vid;

	mutex_lock(&esw->fdb_mutex);
	ret = ralink_esw_atu_write(esw, addr, fdb_vid, BIT(port),
			   RALINK_ESW_ATU_AGE_STATIC, false);
	mutex_unlock(&esw->fdb_mutex);

	return ret;
}

static int ralink_esw_port_fdb_del(struct dsa_switch *ds, int port,
				   const unsigned char *addr, u16 vid,
				   struct dsa_db db)
{
	struct ralink_esw *esw = ds->priv;
	int ret, fdb_vid = vid;

	if (!fdb_vid)
		fdb_vid = ralink_esw_db_vid(db);

	if (fdb_vid < 0)
		return fdb_vid;

	mutex_lock(&esw->fdb_mutex);
	ret = ralink_esw_atu_write(esw, addr, fdb_vid, 0,
			   RALINK_ESW_ATU_AGE_INVALID, false);
	mutex_unlock(&esw->fdb_mutex);

	return ret;
}

static int ralink_esw_port_mdb_add(struct dsa_switch *ds, int port,
				   const struct switchdev_obj_port_mdb *mdb,
				   struct dsa_db db)
{
	struct ralink_esw *esw = ds->priv;
	struct ralink_esw_atu_entry ent;
	u8 port_mask;
	int ret, mdb_vid = mdb->vid;

	if (!mdb_vid)
		mdb_vid = ralink_esw_db_vid(db);

	if (mdb_vid < 0)
		return mdb_vid;

	mutex_lock(&esw->fdb_mutex);
	ret = ralink_esw_atu_find(esw, mdb->addr, mdb_vid, true, &ent);
	if (ret == -ENOENT)
		port_mask = BIT(port);
	else if (ret)
		goto out;
	else
		port_mask = ent.port_mask | BIT(port);

	ret = ralink_esw_atu_write(esw, mdb->addr, mdb_vid, port_mask,
			   RALINK_ESW_ATU_AGE_STATIC, false);
out:
	mutex_unlock(&esw->fdb_mutex);
	return ret;
}

static int ralink_esw_port_mdb_del(struct dsa_switch *ds, int port,
				   const struct switchdev_obj_port_mdb *mdb,
				   struct dsa_db db)
{
	struct ralink_esw *esw = ds->priv;
	struct ralink_esw_atu_entry ent;
	u8 port_mask;
	int ret, mdb_vid = mdb->vid;

	if (!mdb_vid)
		mdb_vid = ralink_esw_db_vid(db);

	if (mdb_vid < 0)
		return mdb_vid;

	mutex_lock(&esw->fdb_mutex);

	ret = ralink_esw_atu_find(esw, mdb->addr, mdb_vid, true, &ent);
	if (ret)
		goto out;

	port_mask = ent.port_mask & ~BIT(port);

	ret = ralink_esw_atu_write(esw, mdb->addr, mdb_vid, port_mask,
				port_mask ? RALINK_ESW_ATU_AGE_STATIC :
					RALINK_ESW_ATU_AGE_INVALID, false);

out:
	mutex_unlock(&esw->fdb_mutex);
	return ret;
}

static int ralink_esw_port_max_mtu(struct dsa_switch *ds, int port)
{
	return RALINK_ESW_MAX_MTU;
}

static int ralink_esw_port_enable(struct dsa_switch *ds, int port,
				  struct phy_device *phy)
{
	struct ralink_esw *esw = ds->priv;
	u32 mask;

	if (!dsa_is_user_port(ds, port))
		return 0;

	mask = BIT(RALINK_ESW_POC0_DIS_PORT_SHIFT + port);
	ralink_esw_rmw(esw, RALINK_ESW_POC0, mask, 0);

	return 0;
}

static void ralink_esw_port_disable(struct dsa_switch *ds, int port)
{
	struct ralink_esw *esw = ds->priv;
	u32 mask;

	if (!dsa_is_user_port(ds, port))
		return;

	mask = BIT(RALINK_ESW_POC0_DIS_PORT_SHIFT + port);
	ralink_esw_rmw(esw, RALINK_ESW_POC0, mask, mask);
}

static void ralink_esw_sdm_set_prio_baseline(struct ralink_esw *esw)
{
	if (!esw->sdm)
		return;

	/* priorities 0..3 -> RX1, 4..7 -> RX0 */
	regmap_update_bits(esw->sdm, SDM_RRING,
			   SDM_PRIO_RING_MASK,
			   GENMASK(3, 0));
}

static void ralink_esw_sdm_set_port_ring(struct ralink_esw *esw,
					 int port, bool rx1)
{
	if (!esw->sdm || port > 4)
		return;

	regmap_update_bits(esw->sdm, SDM_RRING,
			   SDM_PORT_RING_BIT(port),
			   rx1 ? SDM_PORT_RING_BIT(port) : 0);
}

static void ralink_esw_port_set_default_prio(struct ralink_esw *esw,
					     int port, u8 prio)
{
	u32 mask = RALINK_ESW_PFC1_PORT_PRI_MASK(port);
	u32 set = RALINK_ESW_PFC1_PORT_PRI_VAL(port, prio & 0x3);

	ralink_esw_rmw(esw, RALINK_ESW_PFC1, mask, set);
}

static int ralink_esw_port_bridge_join(struct dsa_switch *ds, int port,
				       struct dsa_bridge bridge,
				       bool *tx_fwd_offload,
				       struct netlink_ext_ack *extack)
{
	struct ralink_esw *esw = ds->priv;
	int ret;

	ret = dsa_tag_8021q_bridge_join(ds, port, bridge, tx_fwd_offload,
					extack);
	if (ret)
		return ret;

	/* Bridged traffic uses normal/default priority. */
	ralink_esw_port_set_default_prio(esw, port, 0);
	ralink_esw_sdm_set_port_ring(esw, port, false);

	return 0;
}

static void ralink_esw_port_bridge_leave(struct dsa_switch *ds, int port,
					 struct dsa_bridge bridge)
{
	struct ralink_esw *esw = ds->priv;

	dsa_tag_8021q_bridge_leave(ds, port, bridge);

	/* Standalone traffic uses the reserved steering class. */
	ralink_esw_port_set_default_prio(esw, port, 2);
	ralink_esw_sdm_set_port_ring(esw, port, true);
}

static int ralink_esw_port_pre_bridge_flags(struct dsa_switch *ds, int port,
					    struct switchdev_brport_flags flags,
					    struct netlink_ext_ack *extack)
{
	if (flags.mask & ~BR_LEARNING) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only BR_LEARNING flag is supported");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void ralink_esw_port_stp_state_set(struct dsa_switch *ds, int port,
					  u8 state)
{
	struct ralink_esw *esw = ds->priv;
	u32 mask, set = 0;

	if (!dsa_is_user_port(ds, port))
		return;

	mask = RALINK_ESW_POC1_BLOCKING_BIT(port) |
	       RALINK_ESW_POC1_DIS_LRNING_BIT(port);

	switch (state) {
	case BR_STATE_DISABLED:
	case BR_STATE_BLOCKING:
	case BR_STATE_LISTENING:
		set |= RALINK_ESW_POC1_BLOCKING_BIT(port);
		set |= RALINK_ESW_POC1_DIS_LRNING_BIT(port);
		break;
	case BR_STATE_LEARNING:
		set |= RALINK_ESW_POC1_BLOCKING_BIT(port);
		break;
	case BR_STATE_FORWARDING:
		break;
	default:
		return;
	}

	ralink_esw_rmw(esw, RALINK_ESW_POC1, mask, set);
}

static void ralink_esw_port_set_learning(struct ralink_esw *esw,
					 int port, bool enable)
{
	u32 mask = RALINK_ESW_POC1_DIS_LRNING_BIT(port);

	ralink_esw_rmw(esw, RALINK_ESW_POC1,
		       mask,
		       enable ? 0 : mask);
}

static int ralink_esw_port_bridge_flags(struct dsa_switch *ds, int port,
					struct switchdev_brport_flags flags,
					struct netlink_ext_ack *extack)
{
	struct ralink_esw *esw = ds->priv;

	if (flags.mask & BR_LEARNING) {
		bool learning = flags.val & BR_LEARNING;

		esw->ports[port].learning = learning;

		ralink_esw_port_set_learning(esw, port, learning);
	}

	return 0;
}

static void ralink_esw_port_set_host_flood(struct dsa_switch *ds, int port,
					   bool uc, bool mc)
{
	struct ralink_esw *esw = ds->priv;
	u32 mask, set = 0;

	if (!dsa_is_user_port(ds, port))
		return;

	mask = RALINK_ESW_SOCPC_DISUN2CPU_BIT(port) |
	       RALINK_ESW_SOCPC_DISMC2CPU_BIT(port);

	/* Bits are inverted: 1 = do not forward to CPU */
	if (!uc)
		set |= RALINK_ESW_SOCPC_DISUN2CPU_BIT(port);
	if (!mc)
		set |= RALINK_ESW_SOCPC_DISMC2CPU_BIT(port);

	ralink_esw_rmw(esw, RALINK_ESW_SOCPC, mask, set);
}

static int ralink_esw_cpu_port_detect(struct ralink_esw *esw)
{
	struct dsa_switch *ds = esw->ds;
	int port, cpu_port = -1;

	for (port = 0; port < ds->num_ports; port++) {
		if (!dsa_is_cpu_port(ds, port))
			continue;

		if (cpu_port >= 0)
			return -EINVAL; /* multiple CPU ports */

		cpu_port = port;
	}

	if (cpu_port < 0)
		return -EINVAL;

	esw->cpu_port = cpu_port;

	switch (cpu_port) {
	case 6: return 0;
	case 0: return 1;
	case 4: return 2;
	case 5: return 3;
	default:
		return -EINVAL; /* unsupported encoding */
	}
}

static int ralink_esw_setup(struct dsa_switch *ds)
{
	struct ralink_esw *esw = ds->priv;
	u32 socpc;
	int cpu_enc, i, ret;

	cpu_enc = ralink_esw_cpu_port_detect(esw);
	if (cpu_enc < 0)
		return dev_err_probe(esw->dev, cpu_enc,
			     "invalid CPU port\n");
	/*
	 * - packets sent from the CPU do not require software CRC padding
	 *
	 * Default host flooding policy:
	 * - do not punt unknown unicast to CPU
	 * - do not punt multicast to CPU
	 * - do not punt broadcast to CPU
	 *
	 * Per-port unknown unicast/multicast host flooding may be enabled
	 * later through port_set_host_flood(). Broadcast-to-CPU remains a
	 * fixed global policy.
	 */
	socpc = RALINK_ESW_SOCPC_CRC_PADDING |
		FIELD_PREP(RALINK_ESW_SOCPC_CPU_SELECTION, cpu_enc) |
		FIELD_PREP(RALINK_ESW_SOCPC_DISBC2CPU, 0x7f) |
		FIELD_PREP(RALINK_ESW_SOCPC_DISMC2CPU, 0x7f) |
		FIELD_PREP(RALINK_ESW_SOCPC_DISUN2CPU, 0x7f);

	ralink_esw_w32(esw, RALINK_ESW_SOCPC, socpc);

	/* Enable special tag on the CPU port (selected via DSA/DTS). */
	ralink_esw_rmw(esw, RALINK_ESW_SGC2,
		RALINK_ESW_SGC2_LAN_PMAP |
		RALINK_ESW_SGC2_CPU_TPID_EN |
		RALINK_ESW_SGC2_TX_CPU_TPID_BIT_MAP,
		RALINK_ESW_SGC2_CPU_TPID_EN |
		FIELD_PREP(RALINK_ESW_SGC2_TX_CPU_TPID_BIT_MAP,
			    BIT(esw->cpu_port)));

	/*
	 * Priority/flow classification baseline:
	 * - disable ToS/DSCP classification
	 * - disable VLAN-based classification
	 * - disable IGMP snooping by default
	 * - do not program per-port default priority yet
	 */
	ralink_esw_rmw(esw, RALINK_ESW_PFC1,
		RALINK_ESW_PFC1_CPU_USE_Q1_EN |
		RALINK_ESW_PFC1_EN_TOS |
		RALINK_ESW_PFC1_EN_VLAN |
		RALINK_ESW_PFC1_PRIORITY_OPTION |
		RALINK_ESW_PFC1_IGMP_SNOOP,
		0);

	/*
	 * Switch global control:
	 * - Unknown IP multicast: flood (normal switching)
	 * - Unknown reserved multicast (e.g. BPDUs): forward to CPU
	 * - Disable broadcast storm protection
	 * - Enable address aging
	 * - Set max packet length to support VLAN/DSA frames
	 */
	ralink_esw_rmw(esw, RALINK_ESW_SGC,
		RALINK_ESW_SGC_BKOFF_ALG |
		RALINK_ESW_SGC_LEN_ERR_CHK |
		RALINK_ESW_SGC_IP_MULT_RULE |
		RALINK_ESW_SGC_RMC_RULE |
		RALINK_ESW_SGC_DIS_PKT_TX_ABORT |
		RALINK_ESW_SGC_PKT_MAX_LEN |
		RALINK_ESW_SGC_BC_STORM_PROT |
		RALINK_ESW_SGC_AGING_INTERVAL,
		RALINK_ESW_SGC_BKOFF_ALG |
		RALINK_ESW_SGC_LEN_ERR_CHK |
		FIELD_PREP(RALINK_ESW_SGC_IP_MULT_RULE, 0) |
		FIELD_PREP(RALINK_ESW_SGC_RMC_RULE, 1) |
		FIELD_PREP(RALINK_ESW_SGC_DIS_PKT_TX_ABORT, 0) |
		FIELD_PREP(RALINK_ESW_SGC_PKT_MAX_LEN, 1) |
		FIELD_PREP(RALINK_ESW_SGC_BC_STORM_PROT, 0) |
		FIELD_PREP(RALINK_ESW_SGC_AGING_INTERVAL, 1));

       /*
	* Port control 1 baseline:
	* - do not punt IP multicast to CPU (handled in hardware)
	* - no ports in blocking state (forwarding allowed by default)
	* - enable MAC learning on all ports
	* - disable secure port mode
	*
	* STP state will override blocking and learning per port.
	*/
	ralink_esw_rmw(esw, RALINK_ESW_POC1,
		RALINK_ESW_POC1_DIS_IPMC2CPU |
		RALINK_ESW_POC1_BLOCKING |
		RALINK_ESW_POC1_DIS_LRNING |
		RALINK_ESW_POC1_SA_SECURE_PORT,
		FIELD_PREP(RALINK_ESW_POC1_DIS_IPMC2CPU, 0x7f) |
		FIELD_PREP(RALINK_ESW_POC1_BLOCKING, 0) |
		FIELD_PREP(RALINK_ESW_POC1_DIS_LRNING, 0) |
		FIELD_PREP(RALINK_ESW_POC1_SA_SECURE_PORT, 0));

	/* Port control 2 baseline:
	 * - use per-VLAN untag control
	 * - enable aging on all ports
	 * - do not force per-port untagging
	 * - flood unknown IPv6 multicast
	 * - do not punt MLD to CPU by default
	 */
	ralink_esw_rmw(esw, RALINK_ESW_POC2,
		RALINK_ESW_POC2_DIS_UC_PAUSE |
		RALINK_ESW_POC2_PER_VLAN_UNTAG_EN |
		RALINK_ESW_POC2_ENAGING |
		RALINK_ESW_POC2_UNTAG_EN |
		RALINK_ESW_POC2_MLD2CPU_EN |
		RALINK_ESW_POC2_IPV6_MULT_RULE,
		FIELD_PREP(RALINK_ESW_POC2_DIS_UC_PAUSE, 0) |
		RALINK_ESW_POC2_PER_VLAN_UNTAG_EN |
		FIELD_PREP(RALINK_ESW_POC2_ENAGING, 0x7f) |
		FIELD_PREP(RALINK_ESW_POC2_UNTAG_EN, 0) |
		FIELD_PREP(RALINK_ESW_POC2_MLD2CPU_EN, 0) |
		FIELD_PREP(RALINK_ESW_POC2_IPV6_MULT_RULE, 0));

	bitmap_zero(esw->vlan_slot, RALINK_ESW_NUM_VLANS);

	for (i = 0; i < RALINK_ESW_NUM_VLANS; i++) {
		esw->vlan_vid[i] = RALINK_ESW_VID_NONE;
		esw->vlan_member[i] = 0;
		esw->vlan_untag[i] = 0;
		ralink_esw_set_vlan_vid(esw, i, 0);
		ralink_esw_set_vlan_members(esw, i, 0);
		ralink_esw_set_vlan_untag(esw, i, 0);
	}

	for (i = 0; i < ds->num_ports; i++) {
		esw->ports[i].vlan_filtering = false;
		esw->ports[i].learning = true;
		esw->ports[i].pvid_tag_8021q = 0;
		esw->ports[i].pvid_tag_8021q_configured = false;
		esw->ports[i].pvid_vlan_filtering = 0;
		esw->ports[i].pvid_vlan_filtering_configured = false;
		/* Standalone baseline: use reserved steering class */
		ralink_esw_port_set_default_prio(esw, i, 2);
	}

	ralink_esw_sdm_set_prio_baseline(esw);
	ralink_esw_stats_init(esw);

	rtnl_lock();
	ret = dsa_tag_8021q_register(ds, htons(ETH_P_8021Q));
	rtnl_unlock();

	return ret;
}

static void ralink_esw_teardown(struct dsa_switch *ds)
{
	struct ralink_esw *esw = ds->priv;

	ralink_esw_stats_deinit(esw);

	rtnl_lock();
	dsa_tag_8021q_unregister(ds);
	rtnl_unlock();
}

static enum dsa_tag_protocol ralink_esw_get_tag_protocol(struct dsa_switch *ds,
						 int port,
						 enum dsa_tag_protocol mp)
{
	return DSA_TAG_PROTO_RALINK;
}

static int ralink_esw_rl_calc(u64 rate_bps, u32 *tick_sel, u32 *token)
{
	u64 rate_Bps = DIV_ROUND_UP_ULL(rate_bps, 8);
	int i;

	/* Prefer the smallest tick for best accuracy. */
	for (i = ARRAY_SIZE(ralink_esw_rl_tick_us) - 1; i >= 0; i--) {
		u64 tok;

		tok = DIV_ROUND_CLOSEST_ULL(rate_Bps *
				ralink_esw_rl_tick_us[i],
				1000000ULL);
		/* Ensure min. representable rate (token must be >= 1) */
		if (!tok)
			tok = 1;

		if (tok <= RALINK_ESW_RL_MAX_TOKEN) {
			*tick_sel = i;
			*token = tok;
		return 0;
		}
	}

	return -ERANGE;
}

static int ralink_esw_ingress_program(struct ralink_esw *esw, int port,
				bool enable, u32 tick, u32 token,
				u32 threshold, bool mgmt_bypass)
{
	u32 reg, thres_reg, mask, set = 0;
	u32 shift;

	reg = ralink_esw_ing_ctrl_reg(port);
	thres_reg = ralink_esw_ing_thres_reg(port);
	shift = ralink_esw_rl_shift(port);

	mask = RALINK_ESW_INGRESS_CTRL(shift) |
		RALINK_ESW_INGRESS_FLOW_CTRL(shift) |
		RALINK_ESW_INGRESS_MGMT_BYPASS(shift) |
		RALINK_ESW_INGRESS_TICK(shift) |
		RALINK_ESW_INGRESS_TOKEN(shift);

	if (enable) {
		set |= RALINK_ESW_INGRESS_CTRL(shift);
		set |= (tick << (shift + 10)) &
					RALINK_ESW_INGRESS_TICK(shift);
		set |= (token << shift) & RALINK_ESW_INGRESS_TOKEN(shift);

		if (mgmt_bypass)
			set |= RALINK_ESW_INGRESS_MGMT_BYPASS(shift);

		ralink_esw_rmw(esw, thres_reg,
			RALINK_ESW_INGRESS_FC_ON_THRES,
			FIELD_PREP(RALINK_ESW_INGRESS_FC_ON_THRES,
			threshold));
	}

	ralink_esw_rmw(esw, reg, mask, set);

	return 0;
}

static int ralink_esw_egress_program(struct ralink_esw *esw, int port,
					bool enable, u32 tick, u32 token)
{
	u32 reg, mask, set = 0;
	u32 shift;

	reg = ralink_esw_eg_ctrl_reg(port);
	shift = ralink_esw_rl_shift(port);

	mask = RALINK_ESW_EGRESS_CTRL(shift) |
		RALINK_ESW_EGRESS_TICK(shift) |
		RALINK_ESW_EGRESS_TOKEN(shift);

	if (enable) {
		set |= RALINK_ESW_EGRESS_CTRL(shift);
		set |= (tick << (shift + 10)) & RALINK_ESW_EGRESS_TICK(shift);
		set |= (token << shift) & RALINK_ESW_EGRESS_TOKEN(shift);
	}

	ralink_esw_rmw(esw, reg, mask, set);

	return 0;
}

static int ralink_esw_port_setup_tbf(struct ralink_esw *esw, int port,
					struct tc_tbf_qopt_offload *tbf)
{
	struct tc_ratespec rs;
	u64 rate_bps;
	u32 tick, token;
	int ret;

	if (tbf->command == TC_TBF_DESTROY)
		return ralink_esw_egress_program(esw, port, false, 0, 0);

	if (tbf->command != TC_TBF_REPLACE)
		return -EOPNOTSUPP;

	psched_ratecfg_getrate(&rs, &tbf->replace_params.rate);
	rate_bps = (u64)rs.rate * 8ULL;
	if (!rate_bps)
		return -EINVAL;

	if (tbf->replace_params.max_size > RALINK_ESW_RL_MAX_THRESHOLD)
		return -EOPNOTSUPP;

	ret = ralink_esw_rl_calc(rate_bps, &tick, &token);
	if (ret)
		return ret;

	return ralink_esw_egress_program(esw, port, true, tick, token);
}

static int ralink_esw_port_setup_tc(struct dsa_switch *ds, int port,
				enum tc_setup_type type, void *type_data)
{
	struct ralink_esw *esw = ds->priv;

	if (!dsa_is_user_port(ds, port))
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_QDISC_TBF:
		return ralink_esw_port_setup_tbf(esw, port, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static int ralink_esw_port_policer_add(struct dsa_switch *ds, int port,
		struct dsa_mall_policer_tc_entry *policer)
{
	struct ralink_esw *esw = ds->priv;
	u64 rate_bps;
	u32 tick, token;
	u32 threshold;
	int ret;

	if (!dsa_is_user_port(ds, port))
		return -EOPNOTSUPP;

	if (!policer->rate_bytes_per_sec)
		return -EINVAL;

	rate_bps = policer->rate_bytes_per_sec * 8ULL;

	ret = ralink_esw_rl_calc(rate_bps, &tick, &token);
	if (ret)
		return ret;

	if (!policer->burst)
		return -EINVAL;

	threshold = min_t(u32, policer->burst,
			  RALINK_ESW_RL_MAX_THRESHOLD);

	return ralink_esw_ingress_program(esw, port, true,
					  tick, token,
					  threshold, true);
}

static void ralink_esw_port_policer_del(struct dsa_switch *ds, int port)
{
	struct ralink_esw *esw = ds->priv;

	if (!dsa_is_user_port(ds, port))
		return;

	ralink_esw_ingress_program(esw, port, false, 0, 0, 0, false);
}

static const struct dsa_switch_ops ralink_esw_ops = {
	.get_tag_protocol	= ralink_esw_get_tag_protocol,

	.setup			= ralink_esw_setup,
	.teardown		= ralink_esw_teardown,
	.port_enable		= ralink_esw_port_enable,
	.port_disable		= ralink_esw_port_disable,
	.port_max_mtu		= ralink_esw_port_max_mtu,

	.port_vlan_filtering	= ralink_esw_port_vlan_filtering,
	.port_vlan_add		= ralink_esw_port_vlan_add,
	.port_vlan_del		= ralink_esw_port_vlan_del,

	.port_bridge_join	= ralink_esw_port_bridge_join,
	.port_bridge_leave	= ralink_esw_port_bridge_leave,
	.port_pre_bridge_flags	= ralink_esw_port_pre_bridge_flags,
	.port_bridge_flags	= ralink_esw_port_bridge_flags,
	.port_stp_state_set     = ralink_esw_port_stp_state_set,
	.port_set_host_flood	= ralink_esw_port_set_host_flood,

	.port_fdb_dump		= ralink_esw_port_fdb_dump,
	.port_fdb_add		= ralink_esw_port_fdb_add,
	.port_fdb_del		= ralink_esw_port_fdb_del,
	.port_mdb_add		= ralink_esw_port_mdb_add,
	.port_mdb_del		= ralink_esw_port_mdb_del,

	.tag_8021q_vlan_add	= ralink_esw_tag_8021q_vlan_add,
	.tag_8021q_vlan_del	= ralink_esw_tag_8021q_vlan_del,

	.get_strings		= ralink_esw_get_strings,
	.get_sset_count		= ralink_esw_get_sset_count,
	.get_ethtool_stats	= ralink_esw_get_ethtool_stats,

	.port_setup_tc		= ralink_esw_port_setup_tc,
	.port_policer_add	= ralink_esw_port_policer_add,
	.port_policer_del	= ralink_esw_port_policer_del,

	/* phylink */
	.phylink_get_caps	= ralink_esw_phylink_get_caps,
};

static void ralink_esw_phylink_mac_change(struct ralink_esw *esw, int port,
					  bool up)
{
	struct dsa_port *dp = dsa_to_port(esw->ds, port);

	phylink_mac_change(dp->pl, up);
}

static irqreturn_t ralink_esw_irq_thread(int irq, void *data)
{
	struct ralink_esw *esw = data;
	u32 stat, link, change;
	int port;

	stat = ralink_esw_r32(esw, RALINK_ESW_ISR);
	if (!(stat & RALINK_ESW_PORT_ST_CHG))
		return IRQ_NONE;

	link = ralink_esw_r32(esw, RALINK_ESW_POA) >>
	       RALINK_ESW_POA_LINK_SHIFT;
	change = link ^ esw->link_state;

	for (port = 0; port < RALINK_ESW_NUM_PORTS; port++) {
		if (change & BIT(port))
			ralink_esw_phylink_mac_change(esw, port,
						      !!(link & BIT(port)));
	}

	esw->link_state = link;

	/* Ack interrupt after sampling link state */
	ralink_esw_w32(esw, RALINK_ESW_ISR, stat);

	return IRQ_HANDLED;
}

static int ralink_esw_irq_init(struct ralink_esw *esw)
{
	int irq, ret;

	irq = platform_get_irq_optional(to_platform_device(esw->dev), 0);
	if (irq == -ENXIO)
		return 0;
	if (irq < 0)
		return irq;

	esw->link_state = ralink_esw_r32(esw, RALINK_ESW_POA) >>
			  RALINK_ESW_POA_LINK_SHIFT;

	ret = devm_request_threaded_irq(esw->dev, irq, NULL,
					ralink_esw_irq_thread,
					IRQF_ONESHOT,
					dev_name(esw->dev), esw);
	if (ret) {
		dev_warn(esw->dev,
			 "failed to request link IRQ, falling back to polling\n");
		return 0;
	}

	/* Unmask switch link-change interrupt only */
	ralink_esw_w32(esw, RALINK_ESW_IMR, RALINK_ESW_PORT_ST_CHG);

	return 0;
}

static int ralink_esw_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *sdm_np;
	struct ralink_esw *esw;
	int ret;

	esw = devm_kzalloc(dev, sizeof(*esw), GFP_KERNEL);
	if (!esw)
		return -ENOMEM;

	esw->dev = dev;

	esw->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(esw->base))
		return dev_err_probe(dev, PTR_ERR(esw->base),
					"failed to map registers\n");

	esw->clk = devm_clk_get_optional_enabled(dev, "ephy");
	if (IS_ERR(esw->clk))
		return dev_err_probe(dev, PTR_ERR(esw->clk),
					"failed to enable EPHY clock\n");

	esw->rst_esw = devm_reset_control_get_optional_exclusive(dev, "esw");
	if (IS_ERR(esw->rst_esw))
		return dev_err_probe(dev, PTR_ERR(esw->rst_esw),
					"failed to get ESW reset\n");

	esw->rst_ephy = devm_reset_control_get_optional_exclusive(dev, "ephy");
	if (IS_ERR(esw->rst_ephy))
		return dev_err_probe(dev, PTR_ERR(esw->rst_ephy),
					"failed to get EPHY reset\n");

	if (esw->rst_esw) {
		ret = reset_control_reset(esw->rst_esw);
		if (ret)
			return dev_err_probe(dev, ret,
		"failed to reset ESW\n");
	}

	if (esw->rst_ephy) {
		ret = reset_control_reset(esw->rst_ephy);
		if (ret)
			return dev_err_probe(dev, ret,
						"failed to reset EPHY\n");
	}

	/*
	 * Optional SDM (Switch DMA) syscon.
	 *
	 * SDM is only used for RX steering policy.
	 * Basic switch operation works without it.
	 */
	sdm_np = of_parse_phandle(dev->of_node, "ralink,sdm", 0);
	if (sdm_np) {
		esw->sdm = syscon_node_to_regmap(sdm_np);
		of_node_put(sdm_np);

		if (IS_ERR(esw->sdm)) {
			dev_warn(dev,
			 "SDM syscon unavailable, RX steering disabled\n");
			esw->sdm = NULL;
		}
	} else {
		esw->sdm = NULL;
	}

	esw->ds = devm_kzalloc(dev, sizeof(*esw->ds), GFP_KERNEL);
	if (!esw->ds)
		return -ENOMEM;

	esw->ds->dev = dev;
	esw->ds->priv = esw;
	esw->ds->ops = &ralink_esw_ops;
	esw->ds->phylink_mac_ops = &ralink_esw_phylink_mac_ops;
	esw->ds->num_ports = RALINK_ESW_NUM_PORTS;
	esw->ds->num_tx_queues = 4;

	platform_set_drvdata(pdev, esw);

	mutex_init(&esw->mdio_lock);
	ret = ralink_esw_mdio_register(esw);
	if (ret)
		return ret;

	mutex_init(&esw->fdb_mutex);
	mutex_init(&esw->reg_mutex);

	ret = dsa_register_switch(esw->ds);
	if (ret)
		return dev_err_probe(dev, ret,
		"failed to register DSA switch\n");

	ret = ralink_esw_leds_probe(esw);
	if (ret)
		dev_warn(dev, "failed to register ESW LEDs: %d\n", ret);

	ret = ralink_esw_irq_init(esw);
	if (ret)
		dev_warn(dev, "IRQ init failed: %d\n", ret);

	return 0;
}

static void ralink_esw_remove(struct platform_device *pdev)
{
	struct ralink_esw *esw = platform_get_drvdata(pdev);

	dsa_unregister_switch(esw->ds);
}

static const struct of_device_id ralink_esw_of_match[] = {
	{ .compatible = "ralink,rt5350-esw" },
	{ .compatible = "mediatek,mt7628-esw" },
	{ }
};
MODULE_DEVICE_TABLE(of, ralink_esw_of_match);

static struct platform_driver ralink_esw_driver = {
	.probe  = ralink_esw_probe,
	.remove = ralink_esw_remove,
	.driver = {
	.name = "ralink-esw",
	.of_match_table = ralink_esw_of_match,
	},
};

module_platform_driver(ralink_esw_driver);

MODULE_AUTHOR("Richard van Schagen <richard@routerwrt.org>");
MODULE_DESCRIPTION("DSA driver for Ralink/MediaTek embedded switch (ESW)");
MODULE_LICENSE("GPL");
