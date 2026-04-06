#
# Copyright (C) 2008-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ralink_esw
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/ralink_esw
  SUBMENU:=Network Devices
  TITLE:=dsa-ralink-esw
  DEPENDS:=@TARGET_ramips
  FILES:=$(PKG_BUILD_DIR)/ralink-esw.ko
  AUTOLOAD:=$(call AutoProbe,ralink-esw)
endef

define KernelPackage/ralink_esw/description
  Kernel module for the Ralink ESW switch DSA driver.
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,ralink_esw))
