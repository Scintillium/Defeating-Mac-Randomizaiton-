# Openwrt Makefile for footprints program
# Most of the variables used here are defined in
# the include directives below. We just need to
# specify a basic description of the package, 
# where to find our program, where to find the 
# source files, and where to install the compiled
# program on the router.
#################################################
include $(TOPDIR)/rules.mk
#Name and release number of this package
PKG_NAME:=footprints
PKG_RELEASE:=1
PKG_VERSION:=1.0.0
PKG_USE_MIPS16:=0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_VERSION)


include $(INCLUDE_DIR)/package.mk
# Specify package information for this program
# The variables defined here should be self explanatory
# DEPENDS:=+libpcap +libpthread +libxml2 +libcurl +libuci
define Package/footprints
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=footprints--collect WiFi device information
	DEPENDS:=+libpcap
endef

define Package/footprints/description
 A front end of WiFi devices surveillance system.
endef





# Specify what needs to be done to prepare for building the package.
# In this case, I try to copy the source files to the build directory.
# This is NOT the default. The default uses the PKG_SOURCE_URL and the 
# PKG_SOURCE which is not defined here to download the source from the web.
# In order to just build a simple program that we have just written, it is
# much easier to do it this way.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

# We do not need to difine Build/Configure or Build/Compile directives
# The default are appropriate for compiling a simple program such as this one

# Specify where and how to install the program. Since we only have one file,
# the footprints executable, install it by copying it to the /bin directory on
# the rounter. The  '$(1)' variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install 
# directory if it does not already exist. Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
# $(CP) $(PKG_BUILD_DIR)/setchan.sh $(1)/bin/
# $(INSTALL_DIR) $(1)/etc/config
# $(CP) $(PKG_BUILD_DIR)/footprints.conf $(1)/etc/config/footprints
define Package/footprints/install
		$(INSTALL_DIR) $(1)/bin
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/footprints $(1)/bin/
endef




# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to 
# build a package.
$(eval $(call BuildPackage,footprints))

