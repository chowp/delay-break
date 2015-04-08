#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=delay-break
PKG_VERSION:=1.0
PKG_RELEASE:=1

#depend:=libpcap
#depend+=libpcap
#	

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/delay-break
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpcap +libpthread
	TITLE:=Wireless INterference Graph
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/delay-break/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/delay-break $(1)/usr/sbin  
endef	


#define Package/hello/install
#	$(INSTALL_DIR) $(1)/usr/sbin
#endef
#$(INSTALL_BIN) $(PKG_BUILD_DIR)/hello $(1)/usr/sbin/

$(eval $(call BuildPackage,delay-break,+libpcap))

