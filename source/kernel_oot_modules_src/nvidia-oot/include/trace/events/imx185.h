/* SPDX-License-Identifier: GPL-2.0 */
/*
 * imx185.h
 *
 * Copyright (c) 2017-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM imx185

#if !defined(_TRACE_IMX185_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IMX185_H

#include <linux/tracepoint.h>

TRACE_EVENT(imx185_s_stream,
	TP_PROTO(const char *name, int enable, int mode),
	TP_ARGS(name, enable, mode),
	TP_STRUCT__entry(
		__string(name,	name)
		__field(int,	enable)
		__field(int,	mode)
	),
	TP_fast_assign(
		__assign_str(name, name);
		__entry->enable = enable;
		__entry->mode = mode;
	),
	TP_printk("%s: on %d mode %d", __get_str(name),
		  __entry->enable, __entry->mode)
);


#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
