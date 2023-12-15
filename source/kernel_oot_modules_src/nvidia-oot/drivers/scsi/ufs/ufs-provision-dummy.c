// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015-2023 NVIDIA CORPORATION & AFFILIATES.  All rights reserved.

#include <linux/version.h>
#include "ufs-provision.h"
#include "ufs-tegra.h"
#ifdef CONFIG_DEBUG_FS

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
#include <drivers-private/scsi/ufs/k515/ufshcd.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#include <drivers-private/scsi/ufs/k516/ufshcd.h>
#else
#include <drivers-private/scsi/ufs/k61/ufshcd.h>
#endif

void debugfs_provision_init(struct ufs_hba *hba, struct dentry *device_root)
{
}

void debugfs_provision_exit(struct ufs_hba *hba)
{
}
#endif
