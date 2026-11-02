include $(TOPDIR)/rules.mk

PKG_NAME:=roamd
PKG_VERSION:=1.3.7-r1
PKG_RELEASE:=

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=LaKardo

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS += -DROAMD_VERSION=$(PKG_VERSION)

define Package/roamd
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=wireless
  TITLE:=Wi-Fi band steering and fast roaming daemon
  DEPENDS:=+libubox +libubus +libuci +libblobmsg-json +libuclient +ca-bundle
  CONFLICTS:=usteer dawn
  EXTRA_DEPENDS:=$(if $(CONFIG_USE_APK),!usteer (>=0)$(comma) !dawn (>=0))
  URL:=https://github.com/LaKardo/roamd
endef

define Package/roamd/description
  Seamless Wi-Fi roaming for OpenWrt. Steers dual-band clients between the
  2.4 GHz and 5 GHz interfaces of the same SSID using 802.11v BSS Transition
  Management, keeps 802.11k neighbour reports in sync between the local BSSes and
  provisions 802.11r fast transition in the wireless configuration.
  BSS Transition needs 802.11v (WNM), which the basic and mini wpad builds are
  compiled without: hostapd rejects the bss_transition and wnm_sleep_mode options
  and leaves every BSS disabled. The daemon therefore installs a full wpad build
  itself (roamd deps-ensure, run on service start and during node enrollment),
  keeping the TLS backend the device already uses.
endef

define Package/roamd/conffiles
/etc/config/roamd
endef

define Package/roamd/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
for o in cardinal cardinal_window cardinal_error_max cardinal_delta; do
	uci -q delete roamd.policy.$$o
done
if [ -z "$$(uci -q get roamd.policy.beacon_migrated)" ]; then
	[ "$$(uci -q get roamd.policy.beacon_poll_interval)" = 60000 ] &&
		uci -q set roamd.policy.beacon_poll_interval=0
	uci -q set roamd.policy.beacon_migrated=1
fi
if [ -z "$$(uci -q get roamd.global.ft_ds_migrated)" ]; then
	[ "$$(uci -q get roamd.global.ft_over_ds)" = 1 ] &&
		uci -q set roamd.global.ft_over_ds=0
	uci -q set roamd.global.ft_ds_migrated=1
fi
uci -q commit roamd
[ "$${ROAMD_NO_RESTART}" = 1 ] && exit 0
/etc/init.d/roamd enabled && /etc/init.d/roamd restart >/dev/null 2>&1
exit 0
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/roamd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/roamd $(1)/usr/sbin/roamd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/roamd.config $(1)/etc/config/roamd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/roamd.init $(1)/etc/init.d/roamd
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/roamd.acl.json $(1)/usr/share/rpcd/acl.d/roamd.json
endef

$(eval $(call BuildPackage,roamd))
