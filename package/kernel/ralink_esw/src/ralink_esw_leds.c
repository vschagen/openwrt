// SPDX-License-Identifier: GPL-2.0
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/leds.h>
#include <linux/property.h>
#include <linux/slab.h>

#include <net/dsa.h>

#include "ralink_esw.h"

struct ralink_esw_led {
	struct ralink_esw	*esw;
	struct led_classdev	cdev;
	struct mutex		lock;
	u8			port;
	u8			mode;
	unsigned long		rules;
	bool			hw_control;
};

static void ralink_esw_led_apply(struct ralink_esw_led *led, u8 mode)
{
	u32 reg = RALINK_ESW_PLED(led->port);

	mutex_lock(&led->lock);
	ralink_esw_rmw(led->esw, reg, RALINK_ESW_PLED_MODE,
		FIELD_PREP(RALINK_ESW_PLED_MODE, mode));
	led->mode = mode;
	mutex_unlock(&led->lock);
}

static int ralink_esw_led_parse_port(struct fwnode_handle *fwnode,
				struct ralink_esw_led *led)
{
	u32 port;

	if (fwnode_property_read_u32(fwnode, "reg", &port))
		return -EINVAL;

	/* LED hardware exists only for front-panel ports 0..4 */
	if (port >= 5)
		return -EINVAL;

	led->port = port;
	mutex_init(&led->lock);

	return 0;
}

/* ---- brightness / blink API ---- */

static int
ralink_esw_led_brightness_set_blocking(struct led_classdev *cdev,
				enum led_brightness brightness)
{
	struct ralink_esw_led *led =
		container_of(cdev, struct ralink_esw_led, cdev);

	led->hw_control = false;
	led->rules = 0;
	led->cdev.brightness = brightness ? 1 : 0;

	ralink_esw_led_apply(led, brightness ?
				RALINK_ESW_LED_ON :
				RALINK_ESW_LED_OFF);

	return 0;
}

static int ralink_esw_led_blink_set(struct led_classdev *cdev,
		unsigned long *delay_on, unsigned long *delay_off)
{
	struct ralink_esw_led *led =
			container_of(cdev, struct ralink_esw_led, cdev);

	/* Hardware supports only a global blink rate */
	led->hw_control = false;
	led->rules = 0;
	*delay_on = 60;
	*delay_off = 60;

	ralink_esw_led_apply(led, RALINK_ESW_LED_BLINK);

	return 0;
}

/* ---- hw_control (netdev trigger offload) ---- */

static int ralink_esw_led_rules_to_mode(unsigned long rules, u8 *mode)
{
	bool tx = test_bit(TRIGGER_NETDEV_TX, &rules);
	bool rx = test_bit(TRIGGER_NETDEV_RX, &rules);
	bool link = test_bit(TRIGGER_NETDEV_LINK, &rules);
	bool l10 = test_bit(TRIGGER_NETDEV_LINK_10, &rules);
	bool l100 = test_bit(TRIGGER_NETDEV_LINK_100, &rules);
	bool l1000 = test_bit(TRIGGER_NETDEV_LINK_1000, &rules);
	bool duplex = test_bit(TRIGGER_NETDEV_FULL_DUPLEX, &rules);

	if (l1000)
		return -EOPNOTSUPP;

	if (l10 && l100)
		return -EOPNOTSUPP;

	/* Speed-specific modes take priority */
	if (l10) {
		if (tx || rx)
			*mode = RALINK_ESW_LED_10M_ACTIVITY;
		else if (link)
			*mode = RALINK_ESW_LED_LINK;
		else
			*mode = RALINK_ESW_LED_10M_ACTIVITY;
		return 0;
	}

	if (l100) {
		if (tx || rx)
			*mode = RALINK_ESW_LED_100M_ACTIVITY;
		else if (link)
			*mode = RALINK_ESW_LED_100M;
		else
			*mode = RALINK_ESW_LED_100M_ACTIVITY;
		return 0;
	}

	if (duplex && (tx || rx))
		return -EOPNOTSUPP;

	if (duplex) {
		*mode = RALINK_ESW_LED_DUPLEX;
		return 0;
	}

	if ((tx || rx) && link) {
		*mode = RALINK_ESW_LED_LINK_ACTIVITY;
		return 0;
	}

	if (tx || rx) {
		*mode = RALINK_ESW_LED_ACTIVITY;
		return 0;
	}

	if (link) {
		*mode = RALINK_ESW_LED_LINK;
		return 0;
	}

	if (!rules)
		return -EOPNOTSUPP;

	return -EOPNOTSUPP;
}

static int
ralink_esw_led_hw_control_is_supported(struct led_classdev *cdev,
					unsigned long rules)
{
	u8 mode;

	return ralink_esw_led_rules_to_mode(rules, &mode);
}

static int ralink_esw_led_hw_control_set(struct led_classdev *cdev,
					unsigned long rules)
{
	struct ralink_esw_led *led =
			container_of(cdev, struct ralink_esw_led, cdev);
	u8 mode;
	int ret;

	ret = ralink_esw_led_rules_to_mode(rules, &mode);
	if (ret)
		return ret;

	ralink_esw_led_apply(led, mode);

	led->rules = rules;
	led->hw_control = true;

	return 0;
}

static int ralink_esw_led_hw_control_get(struct led_classdev *cdev,
						unsigned long *rules)
{
	struct ralink_esw_led *led =
			container_of(cdev, struct ralink_esw_led, cdev);

	if (!led->hw_control)
		return -EINVAL;

	*rules = led->rules;

	return 0;
}

static struct device *
ralink_esw_led_hw_control_get_device(struct led_classdev *cdev)
{
	struct ralink_esw_led *led =
			container_of(cdev, struct ralink_esw_led, cdev);
	struct dsa_port *dp = dsa_to_port(led->esw->ds, led->port);

	if (!dp || !dp->user)
		return NULL;

	return &dp->user->dev;
}

int ralink_esw_leds_probe(struct ralink_esw *esw)
{
	struct device *dev = esw->dev;
	struct fwnode_handle *leds, *fwnode;

	leds = device_get_named_child_node(dev, "leds");
	if (!leds)
		return 0;

	fwnode_for_each_child_node(leds, fwnode) {
		struct led_init_data init_data = {};
		struct ralink_esw_led *led;
		enum led_default_state state;
		u32 reg;
		int ret;

		if (fwnode_property_read_u32(fwnode, "reg", &reg)) {
			dev_warn(dev, "LED node missing reg property\n");
			continue;
		}

		if (reg >= 5) {
			dev_warn(dev, "invalid LED index %u\n", reg);
			continue;
		}

		led = devm_kzalloc(dev, sizeof(*led), GFP_KERNEL);
		if (!led)
			continue;

		led->esw = esw;

		ret = ralink_esw_led_parse_port(fwnode, led);
		if (ret) {
			dev_warn(dev, "failed to parse LED %u\n", reg);
			continue;
		}

		led->cdev.max_brightness = 1;
		led->cdev.brightness_set_blocking =
				ralink_esw_led_brightness_set_blocking;
		led->cdev.blink_set = ralink_esw_led_blink_set;

		led->cdev.hw_control_is_supported =
				ralink_esw_led_hw_control_is_supported;
		led->cdev.hw_control_set =
				ralink_esw_led_hw_control_set;
		led->cdev.hw_control_get =
				ralink_esw_led_hw_control_get;
		led->cdev.hw_control_get_device =
				ralink_esw_led_hw_control_get_device;
		led->cdev.hw_control_trigger = "netdev";

		init_data.fwnode = fwnode;
		init_data.devname_mandatory = true;

		state = led_init_default_state_get(fwnode);
		switch (state) {
		case LEDS_DEFSTATE_ON:
			led->cdev.brightness = 1;
			ralink_esw_led_apply(led, RALINK_ESW_LED_ON);
			break;
		case LEDS_DEFSTATE_KEEP:
			break;
		case LEDS_DEFSTATE_OFF:
		default:
			led->cdev.brightness = 0;
			ralink_esw_led_apply(led, RALINK_ESW_LED_OFF);
			break;
		}

		ret = devm_led_classdev_register_ext(dev, &led->cdev,
							&init_data);
		if (ret) {
			dev_warn(dev, "failed to register LED %u: %d\n",
				reg, ret);
		continue;
		}
	}

	fwnode_handle_put(leds);

	/* Set global default blink rate 60ms */
	ralink_esw_rmw(esw, RALINK_ESW_SGC,
		RALINK_ESW_SGC_LED_FLASH_TIME,
		FIELD_PREP(RALINK_ESW_SGC_LED_FLASH_TIME, 1));

	return 0;
}
