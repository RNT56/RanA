## Buildroot BR2_EXTERNAL makefile for the RanA guest tree.
##
## Required by Buildroot in every BR2_EXTERNAL tree. The RanA base layer adds
## no Buildroot packages of its own (ranad + guest rana are cross-compiled
## pure-Go static binaries installed via a rootfs overlay / post-build hook,
## P9). Kept empty of package includes on purpose.
##
## If a future package is genuinely needed, add:
##   include $(sort $(wildcard $(BR2_EXTERNAL_RANA_PATH)/package/*/*.mk))
