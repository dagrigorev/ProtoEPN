include $(TOPDIR)/rules.mk

PKG_NAME:=epn
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

ifeq ($(EPN_SOURCE_DIR),)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/dagrigorev/ProtoEPN.git
PKG_SOURCE_VERSION:=main
PKG_MIRROR_HASH:=skip
endif

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/epn
  SECTION:=net
  CATEGORY:=Network
  TITLE:=EPN router client
  URL:=https://github.com/dagrigorev/ProtoEPN
  DEPENDS:=+libstdcpp +libpthread +libsodium
endef

define Package/epn/description
  EPN client for OpenWrt routers. It connects to an EPN discovery endpoint and
  exposes a local SOCKS5 proxy on the router.
endef

define Package/luci-app-epn
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for EPN
  DEPENDS:=+epn
  PKGARCH:=all
endef

define Package/luci-app-epn/description
  Minimal LuCI page for configuring the EPN router client and checking the
  discovery endpoint reachability.
endef

ifneq ($(EPN_SOURCE_DIR),)
define Build/Prepare
	$(RM) -r $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(EPN_SOURCE_DIR)/* $(PKG_BUILD_DIR)/
endef
endif

CMAKE_OPTIONS += \
	-DEPN_BUILD_TESTS=OFF \
	-DEPN_BUILD_CLIENT_APPS=ON \
	-DEPN_BUILD_SERVER_APPS=OFF \
	-DEPN_BUILD_DEV_TOOLS=OFF \
	-DEPN_BUILD_DEMO_APPS=OFF \
	-DEPN_ENABLE_PQ_CRYPTO=OFF \
	-DCMAKE_BUILD_TYPE=Release

define Build/Install
endef

define Package/epn/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/epn-tun-client/epn-tun-client $(1)/usr/bin/epn-tun-client
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/epn $(1)/etc/config/epn
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/epn $(1)/etc/init.d/epn
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/usr/libexec/epn-ping $(1)/usr/libexec/epn-ping
	$(INSTALL_BIN) ./files/usr/libexec/epn-status $(1)/usr/libexec/epn-status
endef

define Package/luci-app-epn/install
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./files/usr/share/luci/menu.d/luci-app-epn.json $(1)/usr/share/luci/menu.d/luci-app-epn.json
	$(INSTALL_DIR) $(1)/usr/share/luci/htdocs/luci-static/resources/view/epn
	$(INSTALL_DATA) ./files/usr/share/luci/htdocs/luci-static/resources/view/epn/client.js $(1)/usr/share/luci/htdocs/luci-static/resources/view/epn/client.js
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/luci-app-epn.json $(1)/usr/share/rpcd/acl.d/luci-app-epn.json
endef

$(eval $(call BuildPackage,epn))
$(eval $(call BuildPackage,luci-app-epn))
