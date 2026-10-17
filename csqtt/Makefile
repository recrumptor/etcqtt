# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Пакет csqtt: служба-обёртка (csqtt-ctl) + ядро клиента (upstream amurcanov/csqtt).
# Бинарники собираются ВНЕ SDK (cargo-zigbuild, см. .github/workflows/build.yml) и
# кладутся в files/usr/bin/csqtt и files/usr/libexec/csqtt/csqtt-core перед сборкой пакета.
include $(TOPDIR)/rules.mk

PKG_NAME:=csqtt
# PKG_VERSION — версия ядра upstream (CI подставляет автоматически); PKG_RELEASE — ревизия
# обёртки/упаковки: увеличивайте при любых изменениях в wrapper/ или в файлах пакета.
PKG_VERSION:=2.1.9
PKG_RELEASE:=1

PKG_LICENSE:=PolyForm-Noncommercial-1.0.0
PKG_MAINTAINER:=csqtt-openwrt contributors

include $(INCLUDE_DIR)/package.mk

define Package/csqtt
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=CSQTT tunnel client (single instance, UCI, CAPTCHA helper)
  URL:=https://github.com/amurcanov/csqtt
  DEPENDS:=+kmod-tun
endef

define Package/csqtt/description
  OpenWrt integration for the CSQTT tunnel client: one daemon brings up the csqtt0
  interface (/etc/config/csqtt) with a pool of server profiles (priority/failover/
  failback) and a CAPTCHA helper on port 8443. Interface-only: it installs no
  routes, rules, firewall/NAT or DNS changes. Bundles the upstream core client.
endef

define Package/csqtt/conffiles
/etc/config/csqtt
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/csqtt/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/libexec/csqtt $(1)/etc/config $(1)/etc/init.d $(1)/etc/logrotate.d
	$(INSTALL_BIN) ./files/usr/bin/csqtt $(1)/usr/bin/csqtt
	$(INSTALL_BIN) ./files/usr/libexec/csqtt/csqtt-core $(1)/usr/libexec/csqtt/csqtt-core
	$(INSTALL_CONF) ./files/etc/config/csqtt $(1)/etc/config/csqtt
	$(INSTALL_BIN) ./files/etc/init.d/csqtt $(1)/etc/init.d/csqtt
	$(INSTALL_DATA) ./files/etc/logrotate.d/csqtt $(1)/etc/logrotate.d/csqtt
endef

define Package/csqtt/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ -x /etc/init.d/csqtt ] && /etc/init.d/csqtt enable
exit 0
endef

define Package/csqtt/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/csqtt stop 2>/dev/null
/etc/init.d/csqtt disable 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,csqtt))
