// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2023, NVIDIA Corporation.  All rights reserved.
 *
 * PVA trace log
 */

#include <trace/events/nvpva_ftrace.h>

#include "pva.h"
#include "pva_trace.h"

static void read_linear(struct pva *pva, struct pva_trace_log *trace, u32 toff)
{
	struct pva_trace_header *th = NULL;
	struct pva_trace_block_hdr *bh = NULL;
	struct pva_trace_point *tp = NULL;
	u64 dt;
	u32 i;

	const char *name = pva->pdev->name;

	th = (struct pva_trace_header *)trace->addr;
	bh = (struct pva_trace_block_hdr *)((u8 *)th + th->head_offset);
	while (th->head_offset < toff) {
		tp = (struct pva_trace_point *) ((u8 *)bh + sizeof(*bh));
		dt = bh->start_time;
		for (i = 0 ; i < bh->n_entries ; i++) {
			dt = dt + tp->delta_time;
			nvpva_dbg_info(pva, "delta_time: %llu\t %s\t major: %u\t"
				"minor: %u\t flags: %u\tsequence: %u\targ1:"
				" %u\targ2: %u\n",
				dt, name, tp->major, tp->minor, tp->flags,
				tp->sequence, tp->arg1, tp->arg2);

			trace_nvpva_write(dt, name, tp->major,
				tp->minor, tp->flags, tp->sequence,
				tp->arg1, tp->arg2);
			tp = tp + 1;
		}

		th->head_offset += th->block_size;

		/* head reached end of trace log buffer, break */
		if (th->head_offset >= trace->size) {
			th->head_offset = sizeof(*th);
			break;
		}
		bh = (struct pva_trace_block_hdr *) ((u8 *)th +
			th->head_offset);
	}
}

/* Read trace points from head to tail pointer */
void pva_trace_copy_to_ftrace(struct pva *pva)
{
	struct pva_trace_log *trace;
	struct pva_trace_header *th;
	u32 toff;

	trace = &pva->pva_trace;
	th = (struct pva_trace_header *)trace->addr;

	/*
	 * Read from current head to tail offset. Though tail offset might
	 * get change in background by FW. Read till current tail ONLY.
	 */
	if ((th == NULL) || !th->block_size || !th->head_offset
		|| !th->tail_offset)
		return;

	nvpva_dbg_info(pva, "th->block_size: %u\tth->head_offset: %u\tth->tail_offset: %u\n",
			th->block_size, th->head_offset, th->tail_offset);

	/*
	 * If head_offset and tail_offset are same, nothing to read.
	 */
	if (th->head_offset == th->tail_offset)
		return;

	toff = th->tail_offset;

	if (th->head_offset < toff) {
		/* No circular read */
		read_linear(pva, trace, toff);
	} else {
		/*
		 * Circular read
		 * Read from head to trace_log buffer size
		 */
		read_linear(pva, trace, trace->size);
		/* Read from head to tail  */
		read_linear(pva, trace, toff);
	}
}
