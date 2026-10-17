# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-csqtt
PKG_VERSION:=1.1.0
PKG_RELEASE:=1

PKG_LICENSE:=PolyForm-Noncommercial-1.0.0
PKG_MAINTAINER:=csqtt-openwrt contributors

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-csqtt
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI panel for CSQTT
  PKGARCH:=all
  DEPENDS:=+csqtt +luci-base +rpcd-mod-ucode +ucode-mod-socket +coreutils-timeout
endef

define Package/luci-app-csqtt/description
  LuCI panel for the CSQTT tunnel client: status, profiles, tunnel settings,
  CAPTCHA challenges and logs (rpcd-ucode backend, object "csqtt").
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-csqtt/install
	$(INSTALL_DIR) $(1)/www $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d $(1)/usr/share/rpcd/ucode $(1)/usr/libexec/csqtt
	$(CP) ./files/www/luci-static $(1)/www/
	$(INSTALL_DATA) ./files/usr/share/luci/menu.d/luci-app-csqtt.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/luci-app-csqtt.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_BIN) ./files/usr/share/rpcd/ucode/csqtt $(1)/usr/share/rpcd/ucode/csqtt
	$(INSTALL_BIN) ./files/usr/libexec/csqtt/migrate-shared-settings.sh $(1)/usr/libexec/csqtt/
endef

define Package/luci-app-csqtt/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload 2>/dev/null
	exit 0
}
endef

$(eval $(call BuildPackage,luci-app-csqtt))
