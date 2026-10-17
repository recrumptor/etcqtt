# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Русский перевод панели. Каталог собран заранее (csqtt.ru.lmo), исходного .po нет.
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-i18n-csqtt-ru
PKG_VERSION:=1.1.0
PKG_RELEASE:=1

PKG_LICENSE:=PolyForm-Noncommercial-1.0.0
PKG_MAINTAINER:=csqtt-openwrt contributors

include $(INCLUDE_DIR)/package.mk

define Package/luci-i18n-csqtt-ru
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Translation for luci-app-csqtt - Русский (Russian)
  PKGARCH:=all
  DEPENDS:=+luci-app-csqtt
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-i18n-csqtt-ru/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/i18n/csqtt.ru.lmo $(1)/usr/lib/lua/luci/i18n/csqtt.ru.lmo
	$(INSTALL_BIN) ./files/etc/uci-defaults/luci-i18n-csqtt-ru $(1)/etc/uci-defaults/luci-i18n-csqtt-ru
endef

$(eval $(call BuildPackage,luci-i18n-csqtt-ru))
