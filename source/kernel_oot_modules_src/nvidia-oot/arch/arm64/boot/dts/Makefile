# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022, NVIDIA CORPORATION.  All rights reserved.

objtree = $(srctree)

# Redefine the fixdep command
cmd_and_fixdep =                                                             \
	$(cmd);                                                              \
	$(objtree)/scripts/basic/fixdep $(depfile) $@ '$(make-cmd)' > $(dot-target).cmd;\
	rm -f $(depfile)

include $(oottree)/scripts/Makefile.lib

oot-dtstree = $(oottree)/arch/arm64/boot/dts/nvidia

DTB_LIST := $(dtb-y)
DTBO_LIST := $(dtbo-y)
dtb-y :=
dts_makefile=$(foreach d,$(wildcard $1*), $(call dts_makefile,$(d)/,$(2)) $(if $(findstring Makefile,$(d)),$(d)))
dts_mfiles = $(call dts_makefile, $(oot-dtstree), Makefile)

ifneq ($(dts_mfiles),)
dts-include :=
include $(dts_mfiles)
dtb-y := $(addprefix nvidia/,$(dtb-y))
dtbo-y := $(addprefix nvidia/,$(dtbo-y))
endif

DTC_INCLUDE := $(oottree)/include

DTB_LIST += $(dtb-y)
DTBO_LIST += $(dtbo-y)
DTB_OBJS := $(addprefix $(obj)/,$(DTB_LIST))
DTBO_OBJS := $(addprefix $(obj)/,$(DTBO_LIST))

dtbs: $(DTB_OBJS) $(DTBO_OBJS) FORCE

dtbsclean:
	find $(oot-dtstree) -name *.dtb | xargs rm -rf
	find $(oot-dtstree) -name *.dtbo | xargs rm -rf
	find $(oot-dtstree) -name *.tmp | xargs rm -rf
