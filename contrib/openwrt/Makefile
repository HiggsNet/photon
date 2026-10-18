# Development package for an OpenWrt / ImmortalWrt SDK with the packages feed.
include $(TOPDIR)/rules.mk

PKG_NAME:=photon
PHOTON_VERSION:=0.6.0-rc.13
# APK accepts _rc13; retain the upstream spelling in the binary version.
PKG_VERSION:=0.6.0_rc13
PKG_RELEASE:=3
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16
PKG_ASLR_PIE:=0

# Pass the absolute repository path when copying this directory into an SDK.
# Only source directories are copied; no .git, state, keys or build products.
PHOTON_SOURCE_DIR?=$(realpath $(CURDIR)/../..)
GO_PKG:=github.com/HiggsNet/photon
GO_PKG_BUILD_PKG:=$(GO_PKG)/app/photon
GO_PKG_INSTALL_EXTRA:=internal/observer/web
GO_PKG_LDFLAGS_X:=main.buildDescribe=openwrt-v$(PHOTON_VERSION)-r$(PKG_RELEASE) main.buildDirty=unknown

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

GO_PKG_TARGET_VARS:=$(filter-out CGO_ENABLED=%,$(GO_PKG_TARGET_VARS)) CGO_ENABLED=0
GO_PKG_DEFAULT_LDFLAGS:=-linkmode internal

define Package/photon
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Photon mesh daemon
  URL:=https://github.com/HiggsNet/photon
  DEPENDS:=$(GO_ARCH_DEPENDS) @IPV6 +ip-full +iputils-ping +nftables-json +bird2 +bird2c \
    +kmod-xfrm-interface +kmod-veth +kmod-crypto-gcm +kmod-crypto-hmac \
    +kmod-crypto-sha256 +strongswan +strongswan-charon +strongswan-swanctl \
    +strongswan-mod-kernel-netlink +strongswan-mod-socket-default \
    +strongswan-mod-openssl +strongswan-mod-pubkey +strongswan-mod-pem +strongswan-mod-pkcs1 \
    +strongswan-mod-pkcs8 +strongswan-mod-x509 +strongswan-mod-random
endef

define Package/photon/description
  Photon Linux control plane for OpenWrt and ImmortalWrt. Uses the system's
  charon/VICI and Photon-managed BIRD instances. Requires network namespaces
  in the target kernel. Configure identity and firewall4 before enabling.
endef

define Package/photon/conffiles
/etc/config/photon
/etc/photon/
endef

define Build/Prepare
	test -f "$(PHOTON_SOURCE_DIR)/go.mod"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(addprefix $(PHOTON_SOURCE_DIR)/,app internal pkg third_party go.mod go.sum VERSION) $(PKG_BUILD_DIR)/
endef

define Package/photon/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/libexec/rpcd $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_DIR) -m0700 $(1)/etc/photon
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/photon $(1)/usr/sbin/photon
	$(INSTALL_BIN) ./files/photon.init $(1)/etc/init.d/photon
	$(INSTALL_BIN) ./preflight.sh $(1)/usr/libexec/photon-preflight
	$(INSTALL_BIN) ./files/luci.photon $(1)/usr/libexec/rpcd/luci.photon
	$(INSTALL_CONF) ./files/photon.config $(1)/etc/config/photon
	$(INSTALL_CONF) ./files/config.yaml.example $(1)/etc/photon/config.yaml.example
endef

$(eval $(call BuildPackage,photon))
