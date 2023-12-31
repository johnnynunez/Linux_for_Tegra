// SPDX-License-Identifier: GPL-2.0-only
/*
 * Host1x init for Tegra234 SoCs
 *
 * Copyright (c) 2022-2023, NVIDIA CORPORATION & AFFILIATES. All Rights Reserved.
 */

/* include hw specification */
#include "host1x08.h"
#include "host1x08_hardware.h"

/* include code */
#define HOST1X_HW 8

#include "cdma_hw.c"
#include "channel_hw.c"
#include "debug_hw.c"
#include "intr_general_hw.c"
#include "intr_hw.c"
#include "syncpt_hw.c"

#include "../dev.h"

int host1x08_init(struct host1x *host)
{
	host->channel_op = &host1x_channel_ops;
	host->cdma_op = &host1x_cdma_ops;
	host->cdma_pb_op = &host1x_pushbuffer_ops;
	host->syncpt_op = &host1x_syncpt_ops;
	host->intr_general_op = &host1x_intr_general_ops;
	host->intr_op = &host1x_intr_ops;
	host->debug_op = &host1x_debug_ops;

	return 0;
}
