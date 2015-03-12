#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=hostapd
PKG_VERSION:=2.1
PKG_RELEASE:=1
PKG_REV:=93ee3022dc3fdb6e199a57c14b6cc008fe29d921

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=git://w1.fi/srv/git/hostap.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_PROTO:=git
# PKG_MIRROR_MD5SUM:=4e7c1f97edd7514535056fce54ae053a

PKG_MAINTAINER:=Felix Fietkau <nbd@openwrt.org>

PKG_BUILD_PARALLEL:=1

PKG_BUILD_DEPENDS:= \
	PACKAGE_kmod-ath-11n:ath-11n PACKAGE_kmod-atheros-11n-9.2:atheros-11n-9.2

PKG_CONFIG_DEPENDS:= \
	CONFIG_WPA_SUPPLICANT_NO_TIMESTAMP_CHECK \
	CONFIG_PACKAGE_kmod-ath9k \
	CONFIG_PACKAGE_kmod-mac80211 \
	CONFIG_PACKAGE_kmod-madwifi \
	CONFIG_PACKAGE_kmod-ath-11n \
	CONFIG_PACKAGE_kmod-atheros-11n-9.2 \
	CONFIG_PACKAGE_hostapd \
	CONFIG_PACKAGE_hostapd-mini \
	CONFIG_PACKAGE_wpa-supplicant \
	CONFIG_PACKAGE_wpa-supplicant-mini \
	CONFIG_PACKAGE_wpad \
	CONFIG_PACKAGE_wpad-mini \
	CONFIG_PACKAGE_kmod-hostap \
	CONFIG_WPA_RFKILL_SUPPORT \
	CONFIG_DRIVER_WEXT_SUPPORT \
	CONFIG_DRIVER_11N_SUPPORT

ifneq ($(CONFIG_PACKAGE_wpa-supplicant)),)
    PKG_CONFIG_DEPENDS += \
		CONFIG_WPA_SUPPLICANT_INTERNAL \
		CONFIG_WPA_SUPPLICANT_OPENSSL
endif

include $(INCLUDE_DIR)/package.mk
STAMP_CONFIGURED:=$(STAMP_CONFIGURED)_$(call confvar, CONFIG_PACKAGE_kmod-ath-11n CONFIG_PACKAGE_kmod-atheros-11n-9.2 CONFIG_PACKAGE_wpad CONFIG_PACKAGE_wpad-mini CONFIG_PACKAGE_hostapd CONFIG_PACKAGE_hostapd-mini CONFIG_PACKAGE_wpa-supplicant CONFIG_PACKAGE_wpa-supplicant-mini CONFIG_WPA_SUPPLICANT_NO_TIMESTAMP_CHECK PACKAGE_hostapd-utils PACKAGE_wpa-cli WPA_RFKILL_SUPPORT PACKAGE_wpa-supplicant-p2p)

ifdef_any_of = $(filter-out undefined,$(foreach v,$(1),$(origin $(v))))

ifneq ($(CONFIG_DRIVER_11N_SUPPORT),)
  HOSTAPD_IEEE80211N:=y
endif

DRIVER_MAKEOPTS= \
	CONFIG_DRIVER_NL80211=$(CONFIG_PACKAGE_kmod-ath10k) \
	CONFIG_DRIVER_MADWIFI=$(CONFIG_PACKAGE_kmod-madwifi) \
	CONFIG_DRIVER_HOSTAP=$(CONFIG_PACKAGE_kmod-hostap) \
	CONFIG_IEEE80211N=$(HOSTAPD_IEEE80211N) \
	CONFIG_IEEE80211W=$(CONFIG_PACKAGE_kmod-ath9k) \
	CONFIG_DRIVER_WEXT=$(CONFIG_DRIVER_WEXT_SUPPORT) \
	CONFIG_DRIVER_WEXTAP=$(CONFIG_DRIVER_WEXT_SUPPORT) \
	$(if $(CONFIG_WPA_RFKILL_SUPPORT),NEED_RFKILL=y)

ifeq ($(call ifdef_any_of,CONFIG_PACKAGE_hostapd CONFIG_PACKAGE_hostapd-mini),)
  ifdef CONFIG_WPA_SUPPLICANT_OPENSSL
      DRIVER_MAKEOPTS += CONFIG_TLS=openssl
      TARGET_LDFLAGS += -lcrypto -lssl
  endif
  ifdef CONFIG_WPA_SUPPLICANT_NO_TIMESTAMP_CHECK
    TARGET_CFLAGS += -DNO_TIMESTAMP_CHECK
  endif
  DRIVER_MAKEOPTS += \
	CONFIG_DRIVER_ROBOSWITCH=$(CONFIG_PACKAGE_kmod-switch)
endif

DRV_DEPENDS:=+libnl-tiny @(!TARGET_avr32||BROKEN)

define Package/hostapd/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IEEE 802.1x Authenticator
  URL:=http://hostap.epitest.fi/
  DEPENDS:=$(DRV_DEPENDS)
endef

define Package/hostapd
$(call Package/hostapd/Default)
  TITLE+= (full)
  VARIANT:=full
endef

define Package/hostapd/description
 This package contains a full featured IEEE 802.1x/WPA/EAP/RADIUS
 Authenticator.
endef

define Package/hostapd-mini
$(call Package/hostapd/Default)
  TITLE+= (WPA-PSK only)
  VARIANT:=mini
endef

define Package/hostapd-mini/description
 This package contains a minimal IEEE 802.1x/WPA Authenticator (WPA-PSK only).
endef

define Package/hostapd-utils
  $(call Package/hostapd/Default)
  TITLE+= (utils)
  DEPENDS:=@PACKAGE_hostapd||PACKAGE_hostapd-mini||PACKAGE_wpad||PACKAGE_wpad-mini
endef

define Package/hostapd-utils/description
 This package contains a command line utility to control the
 IEEE 802.1x/WPA/EAP/RADIUS Authenticator.
endef

define Package/wpad/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IEEE 802.1x Authenticator/Supplicant
  URL:=http://hostap.epitest.fi/
endef

define Package/wpad
$(call Package/wpad/Default)
  TITLE+= (full)
  DEPENDS:=$(DRV_DEPENDS) +WPA_SUPPLICANT_OPENSSL:libopenssl
  VARIANT:=wpad-full
endef

define Package/wpad/description
 This package contains a full featured IEEE 802.1x/WPA/EAP/RADIUS
 Authenticator and Supplicant
endef

define Package/wpad-mini
$(call Package/wpad/Default)
  TITLE+= (WPA-PSK only)
  DEPENDS:=$(DRV_DEPENDS)
  VARIANT:=wpad-mini
endef

define Package/wpad-mini/description
 This package contains a minimal IEEE 802.1x/WPA Authenticator and Supplicant (WPA-PSK only).
endef

define Package/wpa-supplicant
  SECTION:=net
  CATEGORY:=Network
  TITLE:=WPA Supplicant
  URL:=http://hostap.epitest.fi/wpa_supplicant/
  DEPENDS:=$(DRV_DEPENDS) +WPA_SUPPLICANT_OPENSSL:libopenssl
  VARIANT:=supplicant-full
endef

define Package/wpa-supplicant/Description
  WPA Supplicant
endef

define Package/wpa-supplicant/config
	source "$(SOURCE)/Config.in"
endef

define Package/wpa-supplicant-p2p
  $(Package/wpa-supplicant)
  TITLE:=WPA Supplicant (with Wi-Fi P2P support)
  DEPENDS:=$(DRV_DEPENDS)
  VARIANT:=supplicant-p2p
endef

define Package/wpa-supplicant-p2p/Description
  WPA Supplicant (with Wi-Fi P2P support)
endef

define Package/wpa-supplicant-mini
  $(Package/wpa-supplicant)
  TITLE:=WPA Supplicant (minimal version)
  DEPENDS:=$(DRV_DEPENDS)
  VARIANT:=supplicant-mini
endef

define Package/wpa-supplicant-mini/Description
  WPA Supplicant (minimal version)
endef

define Package/wpa-cli
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=@PACKAGE_wpa-supplicant||PACKAGE_wpa-supplicant-p2p||PACKAGE_wpad-mini||PACKAGE_wpad
  TITLE:=WPA Supplicant command line interface
endef

define Package/wpa-cli/Description
  WPA Supplicant control utility
endef

TARGET_CPPFLAGS := \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(PKG_BUILD_DIR)/src/crypto \
	$(TARGET_CPPFLAGS) \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE \
	$(if $(CONFIG_WPA_MSG_MIN_PRIORITY),-DCONFIG_MSG_MIN_PRIORITY=$(CONFIG_WPA_MSG_MIN_PRIORITY))

TARGET_CFLAGS += -ffunction-sections -fdata-sections
TARGET_LDFLAGS += -Wl,--gc-sections

define Build/RunMake
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/wpad.$(1)/$(2) \
		$(TARGET_CONFIGURE_OPTS) \
		$(DRIVER_MAKEOPTS) \
		LIBS="$(TARGET_LDFLAGS)" \
		BCHECK= \
		$(3)
endef

define Build/ConfigureTarget
	rm -rf $(PKG_BUILD_DIR)/$(2).$(1)
	mkdir -p $(PKG_BUILD_DIR)/$(2).$(1)
	rm -f $(PKG_BUILD_DIR)/.configured*
	$(CP) \
		$(PKG_BUILD_DIR)/$(2) \
		$(PKG_BUILD_DIR)/src \
		$(PKG_BUILD_DIR)/$(2).$(1)/
	$(CP) ./files/$(2)-$(1).config $(PKG_BUILD_DIR)/$(2).$(1)/$(2)/.config
	$(if $(CONFIG_PACKAGE_kmod-madwifi),,$(SED) 's,^CONFIG_DRIVER_MADWIFI,#CONFIG_DRIVER_MADWIFI,g' $(PKG_BUILD_DIR)/$(2).$(1)/$(2)/.config)
endef

define Build/ConfigureTargetWpad
	rm -rf $(PKG_BUILD_DIR)/wpad/$(2).$(1)
	mkdir -p $(PKG_BUILD_DIR)/wpad.$(1)
	rm -f $(PKG_BUILD_DIR)/.configured*
	$(CP) \
		$(PKG_BUILD_DIR)/wpa_supplicant \
		$(PKG_BUILD_DIR)/hostapd \
		$(PKG_BUILD_DIR)/src \
		$(PKG_BUILD_DIR)/wpad.$(1)/
	$(CP) ./files/wpa_supplicant-$(1).config $(PKG_BUILD_DIR)/wpad.$(1)/wpa_supplicant/.config
	$(CP) ./files/hostapd-$(1).config $(PKG_BUILD_DIR)/wpad.$(1)/hostapd/.config
	$(if $(CONFIG_PACKAGE_kmod-madwifi),,$(SED) 's,^CONFIG_DRIVER_MADWIFI,#CONFIG_DRIVER_MADWIFI,g' $(PKG_BUILD_DIR)/wpad.$(1)/wpa_supplicant/.config)
	$(if $(CONFIG_PACKAGE_kmod-madwifi),,$(SED) 's,^CONFIG_DRIVER_MADWIFI,#CONFIG_DRIVER_MADWIFI,g' $(PKG_BUILD_DIR)/wpad.$(1)/hostapd/.config)
endef

define Build/CompileTarget
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(2).$(1)/$(2) \
		$(TARGET_CONFIGURE_OPTS) \
		$(DRIVER_MAKEOPTS) \
		LIBS="$(TARGET_LDFLAGS)" \
		BCHECK= \
		$(2) $(3)
	$(CP) $(PKG_BUILD_DIR)/$(2).$(1)/$(2)/$(3) $(PKG_BUILD_DIR)/
endef

define Build/CompileTargetWpad
	echo ` \
		$(call Build/RunMake,$(1),hostapd,-s MULTICALL=1 dump_cflags); \
		$(call Build/RunMake,$(1),wpa_supplicant,-s MULTICALL=1 dump_cflags) | \
		sed -e 's,-n ,,g' -e 's,$(TARGET_CFLAGS),,' \
	` > $(PKG_BUILD_DIR)/.cflags
	+$(call Build/RunMake,$(1),hostapd, \
		CFLAGS="$$$$$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		MULTICALL=1 \
		hostapd_cli hostapd_multi.a, \
	)
	+$(call Build/RunMake,$(1),wpa_supplicant, \
		CFLAGS="$$$$$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		MULTICALL=1 \
		wpa_cli wpa_supplicant_multi.a, \
	)
	$(TARGET_CC) -o $(PKG_BUILD_DIR)/wpad.$(1)/wpad \
		$(TARGET_CFLAGS) \
		./files/multicall.c \
		$(PKG_BUILD_DIR)/wpad.$(1)/hostapd/hostapd_multi.a \
		$(PKG_BUILD_DIR)/wpad.$(1)/wpa_supplicant/wpa_supplicant_multi.a \
		$(TARGET_LDFLAGS)
	$(CP) $(PKG_BUILD_DIR)/wpad.$(1)/wpa_supplicant/wpa_cli $(PKG_BUILD_DIR)/
	$(CP) $(PKG_BUILD_DIR)/wpad.$(1)/hostapd/hostapd_cli $(PKG_BUILD_DIR)/
endef

define Package/InstallTemplate
	$(INSTALL_DIR) $$(1)/lib/wifi
	$(INSTALL_DATA) ./files/$(3).sh $$(1)/lib/wifi/$(3).sh
	$(INSTALL_DIR) $$(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(3).$(2)/$(3)/$(3) $$(1)/usr/sbin/
endef

define Package/InstallTemplateWpad
	$(INSTALL_DIR) $$(1)/lib/wifi
	$(INSTALL_DATA) ./files/wpa_supplicant.sh $$(1)/lib/wifi/wpa_supplicant.sh
	$(INSTALL_DATA) ./files/hostapd.sh $$(1)/lib/wifi/hostapd.sh
	$(INSTALL_DIR) $$(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(3).$(2)/$(3) $$(1)/usr/sbin/
	ln -sf wpad $$(1)/usr/sbin/hostapd
	ln -sf wpad $$(1)/usr/sbin/wpa_supplicant
endef

define Package/Template
 ifneq ($(CONFIG_PACKAGE_$(1)),)
  ifeq ($(call ifdef_any_of,CONFIG_PACKAGE_wpad CONFIG_PACKAGE_wpad-mini),)
   define Build/Configure/$(1)
	$(call Build/ConfigureTarget,$(2),$(3))
   endef
   define Build/Compile/$(1)
	$(call Build/CompileTarget,$(2),$(3),$(4))
   endef
   define Package/$(1)/install
	$(call Package/InstallTemplate,$(1),$(2),$(3))
   endef
  else #special wpad case
   define Build/Configure/$(1)
	$(call Build/ConfigureTargetWpad,$(2),$(3))
   endef
   define Build/Compile/$(1)
	$(call Build/CompileTargetWpad,$(2),$(3),$(4))
   endef
   define Package/$(1)/install
	$(call Package/InstallTemplateWpad,$(1),$(2),$(3))
   endef
  endif
 endif
endef

define Build/Configure
	rm -f $(PKG_BUILD_DIR)/.configured*
	$(call Build/Configure/hostapd)
	$(call Build/Configure/hostapd-mini)
	$(call Build/Configure/wpa-supplicant)
	$(call Build/Configure/wpa-supplicant-mini)
	$(call Build/Configure/wpad)
	$(call Build/Configure/wpad-mini)
endef

define Build/Compile
	$(call Build/Compile/hostapd)
	$(call Build/Compile/hostapd-mini)
	$(call Build/Compile/wpa-supplicant)
	$(call Build/Compile/wpa-supplicant-mini)
	$(call Build/Compile/wpad)
	$(call Build/Compile/wpad-mini)
endef

define Build/Clean
	rm -rf $(PKG_BUILD_DIR)_full
	rm -rf $(PKG_BUILD_DIR)_mini
endef

define Package/hostapd-utils/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hostapd_cli $(1)/usr/sbin/
endef

define Package/wpa-cli/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wpa_cli $(1)/usr/sbin/
endef

$(eval $(call Package/Template,hostapd,full,hostapd,hostapd_cli))
$(eval $(call Package/Template,hostapd-mini,mini,hostapd,hostapd_cli))
$(eval $(call Package/Template,wpa-supplicant,full,wpa_supplicant,wpa_cli))
$(eval $(call Package/Template,wpa-supplicant-mini,mini,wpa_supplicant,wpa_cli))
$(eval $(call Package/Template,wpad,full,wpad))
$(eval $(call Package/Template,wpad-mini,mini,wpad))

$(eval $(call BuildPackage,hostapd))
$(eval $(call BuildPackage,hostapd-mini))
$(eval $(call BuildPackage,wpad))
$(eval $(call BuildPackage,wpad-mini))
$(eval $(call BuildPackage,wpa-supplicant))
$(eval $(call BuildPackage,wpa-supplicant-mini))
$(eval $(call BuildPackage,wpa-supplicant-p2p))
$(eval $(call BuildPackage,wpa-cli))
$(eval $(call BuildPackage,hostapd-utils))
