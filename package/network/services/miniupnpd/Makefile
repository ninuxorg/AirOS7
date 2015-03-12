#
# Copyright (C) 2006-2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=miniupnpd
PKG_VERSION:=1.8.20130426
PKG_RELEASE:=1

PKG_SOURCE_URL:=http://miniupnp.free.fr/files
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MD5SUM:=ca5344eba200e4a6d1313849d68310f6

include $(INCLUDE_DIR)/package.mk

SHORT_UBNT_FIRMWARE_VERSION=$(shell echo $(CONFIG_UBNT_FIRMWARE_VERSION) | sed "s/^.*\.v/v/g")

define Package/miniupnpd
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+iptables +libip4tc +IPV6:libip6tc +libnfnetlink
  TITLE:=Lightweight UPnP daemon
  SUBMENU:=Firewall
  URL:=http://miniupnp.free.fr/
  MAINTAINER:=Daniel Dickinson <openwrt@cshore.neomailbox.net>
endef

define Package/miniupnpd/conffiles
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	echo "Ubiquiti/$(SHORT_UBNT_FIRMWARE_VERSION)" | tr \(\)\  _ >$(PKG_BUILD_DIR)/os.openwrt
endef

MAKE_FLAGS += \
	LIBS="" \
	CC="$(TARGET_CC) -DIPTABLES_143 -DOS_VERSION=\\\"$(SHORT_UBNT_FIRMWARE_VERSION)\\\" -lnfnetlink -lip4tc $(if $(CONFIG_IPV6),-lip6tc)" \
	CONFIG_OPTIONS="$(if $(CONFIG_IPV6_disabled_by_UBNT_),--ipv6) --leasefile" \
	-f Makefile.linux \
	miniupnpd

define Package/miniupnpd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/miniupnpd $(1)/usr/bin/miniupnpd
endef

$(eval $(call BuildPackage,miniupnpd))
