/*
 * Copyright (c) 2014-2023, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <uapi/linux/nvgpu.h>
#include <linux/anon_inodes.h>

#include <nvgpu/kmem.h>
#include <nvgpu/log.h>
#include <nvgpu/os_sched.h>
#include <nvgpu/gk20a.h>
#include <nvgpu/gr/config.h>
#include <nvgpu/gr/gr.h>
#include <nvgpu/gr/gr_instances.h>
#include <nvgpu/gr/gr_utils.h>
#include <nvgpu/channel.h>
#include <nvgpu/tsg.h>
#include <nvgpu/fifo.h>
#include <nvgpu/nvgpu_init.h>
#include <nvgpu/grmgr.h>
#include <nvgpu/ltc.h>
#include <nvgpu/nvs.h>

#include "platform_gk20a.h"
#include "ioctl_ctrl.h"
#include "ioctl_tsg.h"
#include "ioctl_as.h"
#include "ioctl_channel.h"
#include "ioctl_nvs.h"
#include "ioctl.h"
#include "os_linux.h"

struct tsg_private {
	struct gk20a *g;
	struct nvgpu_tsg *tsg;
	struct nvgpu_cdev *cdev;
	struct gk20a_ctrl_priv *ctrl_priv;
};

extern const struct file_operations gk20a_tsg_ops;

struct nvgpu_tsg *nvgpu_tsg_get_from_file(int fd)
{
	struct nvgpu_tsg *tsg;
	struct tsg_private *priv;
	struct file *f = fget(fd);

	if (!f) {
		return NULL;
	}

	if (f->f_op != &gk20a_tsg_ops) {
		fput(f);
		return NULL;
	}

	priv = (struct tsg_private *)f->private_data;
	tsg = priv->tsg;
	fput(f);
	return tsg;
}

static int nvgpu_tsg_bind_channel_fd(struct nvgpu_tsg *tsg, int ch_fd)
{
	struct nvgpu_channel *ch;
	int err;

	ch = nvgpu_channel_get_from_file(ch_fd);
	if (!ch)
		return -EINVAL;

	err = nvgpu_tsg_create_sync_subcontext_internal(ch->g, tsg, ch);
	if (err != 0) {
		nvgpu_err(ch->g, "sync subctx created failed %d", err);
		return err;
	}

	err = nvgpu_tsg_validate_ch_subctx_vm(ch->g, tsg, ch);
	if (err != 0) {
		nvgpu_err(ch->g, "channel/subctx VM mismatch");
		return err;
	}

	err = nvgpu_tsg_bind_channel(tsg, ch);

	nvgpu_channel_put(ch);
	return err;
}

static int gk20a_tsg_ioctl_bind_channel_ex(struct gk20a *g,
	struct tsg_private *priv, struct nvgpu_tsg_bind_channel_ex_args *arg)
{
	struct nvgpu_tsg *tsg = priv->tsg;
	struct nvgpu_sched_ctrl *sched = &g->sched_ctrl;
	struct nvgpu_channel *ch;
	u32 max_subctx_count;
	u32 gpu_instance_id;
	int err = 0;

	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_sched, "tsgid=%u", tsg->tsgid);

	nvgpu_mutex_acquire(&sched->control_lock);
	if (sched->control_locked) {
		err = -EPERM;
		goto mutex_release;
	}
	err = gk20a_busy(g);
	if (err) {
		nvgpu_err(g, "failed to power on gpu");
		goto mutex_release;
	}

	ch = nvgpu_channel_get_from_file(arg->channel_fd);
	if (!ch) {
		err = -EINVAL;
		goto idle;
	}

	gpu_instance_id = nvgpu_get_gpu_instance_id_from_cdev(g, priv->cdev);
	nvgpu_assert(gpu_instance_id < g->mig.num_gpu_instances);

	max_subctx_count = nvgpu_grmgr_get_gpu_instance_max_veid_count(g, gpu_instance_id);

	if (arg->subcontext_id < max_subctx_count) {
		ch->subctx_id = arg->subcontext_id;
	} else {
		err = -EINVAL;
		goto ch_put;
	}

	nvgpu_log(g, gpu_dbg_info, "channel id : %d : subctx: %d",
				ch->chid, ch->subctx_id);

	/* Use runqueue selector 1 for all ASYNC ids */
	if (ch->subctx_id > CHANNEL_INFO_VEID0)
		ch->runqueue_sel = 1;

	err = nvgpu_tsg_create_sync_subcontext_internal(g, tsg, ch);
	if (err != 0) {
		nvgpu_err(ch->g, "sync subctx created failed %d", err);
		goto ch_put;
	}

	err = nvgpu_tsg_validate_ch_subctx_vm(g, tsg, ch);
	if (err != 0) {
		nvgpu_err(g, "channel/subctx VM mismatch");
		goto ch_put;
	}

	err = nvgpu_tsg_bind_channel(tsg, ch);
ch_put:
	nvgpu_channel_put(ch);
idle:
	gk20a_idle(g);
mutex_release:
	nvgpu_mutex_release(&sched->control_lock);
	return err;
}

static int nvgpu_tsg_unbind_channel_fd(struct nvgpu_tsg *tsg, int ch_fd)
{
	struct nvgpu_channel *ch;
	int err = 0;

	ch = nvgpu_channel_get_from_file(ch_fd);
	if (!ch) {
		return -EINVAL;
	}

	if (tsg != nvgpu_tsg_from_ch(ch)) {
		err = -EINVAL;
		goto out;
	}

	err = nvgpu_tsg_unbind_channel(tsg, ch, false);
	if (err == -EAGAIN) {
		goto out;
	}

	/*
	 * Mark the channel unserviceable since channel unbound from TSG
	 * has no context of its own so it can't serve any job
	 */
	nvgpu_channel_set_unserviceable(ch);

out:
	nvgpu_channel_put(ch);
	return err;
}

#ifdef CONFIG_NVS_PRESENT
static int nvgpu_tsg_bind_scheduling_domain(struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_bind_scheduling_domain_args *args)
{
	struct nvgpu_nvs_domain *domain;
	int err;

	if (args->reserved0 != 0) {
		return -EINVAL;
	}

	if (args->reserved[0] != 0) {
		return -EINVAL;
	}

	if (args->reserved[1] != 0) {
		return -EINVAL;
	}

	if (args->reserved[2] != 0) {
		return -EINVAL;
	}

	if (tsg->g->scheduler == NULL) {
		return -ENOSYS;
	}

	domain = nvgpu_nvs_domain_get_from_file(args->domain_fd);
	if (domain == NULL) {
		return -ENOENT;
	}

	err = nvgpu_tsg_bind_domain(tsg, domain);

	nvgpu_nvs_domain_put(tsg->g, domain);

	return err;
}
#endif

#ifdef CONFIG_NVGPU_CHANNEL_TSG_CONTROL
/*
 * Convert common event_id of the form NVGPU_EVENT_ID_* to Linux specific
 * event_id of the form NVGPU_IOCTL_CHANNEL_EVENT_ID_* which is used in IOCTLs
 */
static u32 nvgpu_event_id_to_ioctl_channel_event_id(
					enum nvgpu_event_id_type event_id)
{
	switch (event_id) {
	case NVGPU_EVENT_ID_BPT_INT:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_BPT_INT;
	case NVGPU_EVENT_ID_BPT_PAUSE:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_BPT_PAUSE;
	case NVGPU_EVENT_ID_BLOCKING_SYNC:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_BLOCKING_SYNC;
	case NVGPU_EVENT_ID_CILP_PREEMPTION_STARTED:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_CILP_PREEMPTION_STARTED;
	case NVGPU_EVENT_ID_CILP_PREEMPTION_COMPLETE:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_CILP_PREEMPTION_COMPLETE;
	case NVGPU_EVENT_ID_GR_SEMAPHORE_WRITE_AWAKEN:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_GR_SEMAPHORE_WRITE_AWAKEN;
	case NVGPU_EVENT_ID_MAX:
		return NVGPU_IOCTL_CHANNEL_EVENT_ID_MAX;
	}

	return NVGPU_IOCTL_CHANNEL_EVENT_ID_MAX;
}

void nvgpu_tsg_post_event_id(struct nvgpu_tsg *tsg,
			     enum nvgpu_event_id_type event_id)
{
	struct gk20a_event_id_data *channel_event_id_data;
	u32 channel_event_id;
	struct gk20a *g = tsg->g;

	channel_event_id = nvgpu_event_id_to_ioctl_channel_event_id(event_id);
	if (event_id >= NVGPU_IOCTL_CHANNEL_EVENT_ID_MAX)
		return;


	nvgpu_mutex_acquire(&tsg->event_id_list_lock);
	nvgpu_list_for_each_entry(channel_event_id_data, &tsg->event_id_list,
					gk20a_event_id_data, event_id_node) {
		if (channel_event_id_data->event_id == event_id) {
			nvgpu_mutex_acquire(&channel_event_id_data->lock);

			nvgpu_log_info(g,
				"posting event for event_id=%d on tsg=%d\n",
				channel_event_id, tsg->tsgid);
			channel_event_id_data->event_posted = true;

			nvgpu_cond_broadcast_interruptible(&channel_event_id_data->event_id_wq);

			nvgpu_mutex_release(&channel_event_id_data->lock);
		}
	}
	nvgpu_mutex_release(&tsg->event_id_list_lock);
}

static unsigned int gk20a_event_id_poll(struct file *filep, poll_table *wait)
{
	unsigned int mask = 0;
	struct gk20a_event_id_data *event_id_data = filep->private_data;
	struct gk20a *g = event_id_data->g;
	u32 event_id = event_id_data->event_id;
	struct nvgpu_tsg *tsg = g->fifo.tsg + event_id_data->id;

	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_info, " ");

	poll_wait(filep, &event_id_data->event_id_wq.wq, wait);

	nvgpu_mutex_acquire(&event_id_data->lock);

	if (event_id_data->event_posted) {
		nvgpu_log_info(g,
			"found pending event_id=%d on TSG=%d\n",
			event_id, tsg->tsgid);
		mask = (POLLPRI | POLLIN);
		event_id_data->event_posted = false;
	}

	nvgpu_mutex_release(&event_id_data->lock);

	return mask;
}

static int gk20a_event_id_release(struct inode *inode, struct file *filp)
{
	struct gk20a_event_id_data *event_id_data = filp->private_data;
	struct gk20a *g;
	struct nvgpu_tsg *tsg;

	if (event_id_data == NULL)
		return -EINVAL;

	g = event_id_data->g;
	tsg = g->fifo.tsg + event_id_data->id;

	nvgpu_mutex_acquire(&tsg->event_id_list_lock);
	nvgpu_list_del(&event_id_data->event_id_node);
	nvgpu_mutex_release(&tsg->event_id_list_lock);

	nvgpu_mutex_destroy(&event_id_data->lock);
	nvgpu_put(g);
	nvgpu_kfree(g, event_id_data);
	filp->private_data = NULL;

	return 0;
}

const struct file_operations gk20a_event_id_ops = {
	.owner = THIS_MODULE,
	.poll = gk20a_event_id_poll,
	.release = gk20a_event_id_release,
};

static int gk20a_tsg_event_id_enable(struct nvgpu_tsg *tsg,
					 int event_id,
					 int *fd)
{
	int err = 0;
	int local_fd;
	struct file *file;
	char name[64];
	struct gk20a_event_id_data *event_id_data;
	struct gk20a *g;

	g = nvgpu_get(tsg->g);
	if (!g)
		return -ENODEV;

	err = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (err < 0)
		goto free_ref;
	local_fd = err;

	(void) snprintf(name, sizeof(name), "nvgpu-event%d-fd%d",
		 event_id, local_fd);

	event_id_data = nvgpu_kzalloc(tsg->g, sizeof(*event_id_data));
	if (!event_id_data) {
		err = -ENOMEM;
		goto clean_up;
	}
	event_id_data->g = g;
	event_id_data->id = tsg->tsgid;
	event_id_data->event_id = event_id;

	nvgpu_cond_init(&event_id_data->event_id_wq);
	nvgpu_mutex_init(&event_id_data->lock);

	nvgpu_init_list_node(&event_id_data->event_id_node);

	file = anon_inode_getfile(name, &gk20a_event_id_ops,
				event_id_data, O_RDWR);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto clean_up_free;
	}

	nvgpu_mutex_acquire(&tsg->event_id_list_lock);
	nvgpu_list_add_tail(&event_id_data->event_id_node, &tsg->event_id_list);
	nvgpu_mutex_release(&tsg->event_id_list_lock);

	fd_install(local_fd, file);

	*fd = local_fd;

	return 0;

clean_up_free:
	nvgpu_kfree(g, event_id_data);
clean_up:
	put_unused_fd(local_fd);
free_ref:
	nvgpu_put(g);
	return err;
}

static int gk20a_tsg_event_id_ctrl(struct gk20a *g, struct nvgpu_tsg *tsg,
		struct nvgpu_event_id_ctrl_args *args)
{
	int err = 0;
	int fd = -1;

	if (args->event_id >= NVGPU_IOCTL_CHANNEL_EVENT_ID_MAX)
		return -EINVAL;

	nvgpu_speculation_barrier();
	switch (args->cmd) {
	case NVGPU_IOCTL_CHANNEL_EVENT_ID_CMD_ENABLE:
		err = gk20a_tsg_event_id_enable(tsg, args->event_id, &fd);
		if (!err)
			args->event_fd = fd;
		break;

	default:
		nvgpu_err(tsg->g, "unrecognized tsg event id cmd: 0x%x",
			   args->cmd);
		err = -EINVAL;
		break;
	}

	return err;
}
#endif /* CONFIG_NVGPU_CHANNEL_TSG_CONTROL */

#ifdef CONFIG_NVGPU_TSG_SHARING
static inline struct nvgpu_tsg_ctrl_dev_node *
nvgpu_tsg_ctrl_dev_node_from_tsg_entry(struct nvgpu_list_node *node)
{
	return (struct nvgpu_tsg_ctrl_dev_node *)
	   ((uintptr_t)node - offsetof(struct nvgpu_tsg_ctrl_dev_node, tsg_entry));
};

static void nvgpu_tsg_remove_ctrl_dev_inst_id(struct nvgpu_tsg *tsg,
					struct gk20a_ctrl_priv *ctrl_priv)
{
	struct nvgpu_tsg_ctrl_dev_node *node, *tmp;
	struct gk20a *g = tsg->g;

	nvgpu_mutex_acquire(&tsg->tsg_share_lock);

	nvgpu_list_for_each_entry_safe(node, tmp, &tsg->ctrl_devices_list,
				  nvgpu_tsg_ctrl_dev_node, tsg_entry) {
		if (node->device_instance_id ==
				nvgpu_gpu_get_device_instance_id(ctrl_priv)) {
			nvgpu_log_info(g, "removing ctrl dev id %llx",
				       nvgpu_gpu_get_device_instance_id(ctrl_priv));
			nvgpu_list_del(&node->tsg_entry);
			nvgpu_kfree(g, node);
		}
	}

	nvgpu_mutex_release(&tsg->tsg_share_lock);
}

static int nvgpu_tsg_add_ctrl_dev_inst_id(struct nvgpu_tsg *tsg,
					  struct gk20a_ctrl_priv *ctrl_priv)
{
	struct nvgpu_tsg_ctrl_dev_node *ctrl_dev_node;
	struct gk20a *g = tsg->g;

	ctrl_dev_node = (struct nvgpu_tsg_ctrl_dev_node *) nvgpu_kzalloc(g,
				sizeof(struct nvgpu_tsg_ctrl_dev_node));
	if (ctrl_dev_node == NULL) {
		nvgpu_err(g, "ctrl_dev_node alloc failed");
		return -ENOMEM;
	}

	nvgpu_init_list_node(&ctrl_dev_node->tsg_entry);
	ctrl_dev_node->device_instance_id =
			nvgpu_gpu_get_device_instance_id(ctrl_priv);

	nvgpu_mutex_acquire(&tsg->tsg_share_lock);
	nvgpu_list_add_tail(&ctrl_dev_node->tsg_entry, &tsg->ctrl_devices_list);
	nvgpu_mutex_release(&tsg->tsg_share_lock);

	nvgpu_log_info(g, "added ctrl dev id %llx",
		       nvgpu_gpu_get_device_instance_id(ctrl_priv));

	return 0;
}

static bool nvgpu_tsg_is_authorized_ctrl_device_id(struct nvgpu_tsg *tsg,
					      u64 device_instance_id)
{
	struct nvgpu_tsg_ctrl_dev_node *node;
	bool authorized = false;

	nvgpu_mutex_acquire(&tsg->tsg_share_lock);

	nvgpu_list_for_each_entry(node, &tsg->ctrl_devices_list,
				  nvgpu_tsg_ctrl_dev_node, tsg_entry) {
		if (node->device_instance_id == device_instance_id) {
			authorized = true;
			break;
		}
	}

	nvgpu_mutex_release(&tsg->tsg_share_lock);

	return authorized;
}

static int nvgpu_tsg_ioctl_get_share_token(struct gk20a *g,
		struct tsg_private *priv,
		struct nvgpu_tsg_get_share_token_args *args)
{
	u64 source_device_instance_id = args->source_device_instance_id;
	u64 target_device_instance_id = args->target_device_instance_id;
	struct nvgpu_tsg *tsg = priv->tsg;
	u32 max_subctx_count;
	u32 gpu_instance_id;
	u64 share_token = 0;
	int err;

	if ((source_device_instance_id == 0UL) ||
	    (target_device_instance_id == 0UL)) {
		nvgpu_err(g, "Invalid source/target device instance id");
		return -EINVAL;
	}

	if (!nvgpu_tsg_is_authorized_ctrl_device_id(tsg,
					       source_device_instance_id)) {
		nvgpu_err(g, "Unauthorized source device instance id");
		return -EINVAL;
	}

	gpu_instance_id = nvgpu_get_gpu_instance_id_from_cdev(g, priv->cdev);
	nvgpu_assert(gpu_instance_id < g->mig.num_gpu_instances);

	max_subctx_count = nvgpu_grmgr_get_gpu_instance_max_veid_count(g, gpu_instance_id);

	nvgpu_mutex_acquire(&tsg->tsg_share_lock);

	if (tsg->share_token_count == max_subctx_count) {
		nvgpu_err(g, "Maximum share tokens are in use");
		nvgpu_mutex_release(&tsg->tsg_share_lock);
		return -ENOSPC;
	}

	err = nvgpu_gpu_get_share_token(g,
					source_device_instance_id,
					target_device_instance_id,
					tsg, &share_token);
	if (err != 0) {
		nvgpu_err(g, "Share token allocation failed %d", err);
		nvgpu_mutex_release(&tsg->tsg_share_lock);
		return err;
	}

	args->share_token = share_token;
	tsg->share_token_count++;

	nvgpu_mutex_release(&tsg->tsg_share_lock);

	return 0;
}

static int nvgpu_tsg_ioctl_revoke_share_token(struct gk20a *g,
		struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_revoke_share_token_args *args)
{
	u64 source_device_instance_id = args->source_device_instance_id;
	u64 target_device_instance_id = args->target_device_instance_id;
	u64 share_token = args->share_token;
	int err;

	if ((source_device_instance_id == 0UL) ||
	    (target_device_instance_id == 0UL) ||
	    (share_token == 0UL)) {
		nvgpu_err(g, "Invalid source/target device instance id or"
			     " share token");
		return -EINVAL;
	}

	if (!nvgpu_tsg_is_authorized_ctrl_device_id(tsg,
					       source_device_instance_id)) {
		nvgpu_err(g, "Unauthorized source device instance id");
		return -EINVAL;
	}

	nvgpu_mutex_acquire(&tsg->tsg_share_lock);

	err = nvgpu_gpu_revoke_share_token(g,
					source_device_instance_id,
					target_device_instance_id,
					share_token, tsg);
	if (err != 0) {
		nvgpu_err(g, "Share token revocation failed %d", err);
		nvgpu_mutex_release(&tsg->tsg_share_lock);
		return err;
	}

	tsg->share_token_count--;

	nvgpu_mutex_release(&tsg->tsg_share_lock);

	return 0;
}
#endif

int nvgpu_ioctl_tsg_open(struct gk20a *g, struct gk20a_ctrl_priv *ctrl_priv,
			 struct nvgpu_cdev *cdev, struct file *filp,
			 bool open_share, u64 source_device_instance_id,
			 u64 target_device_instance_id, u64 share_token)
{
	struct tsg_private *priv;
	struct nvgpu_tsg *tsg;
	struct device *dev;
	int err;

	g = nvgpu_get(g);
	if (!g)
		return -ENODEV;

	dev  = dev_from_gk20a(g);

	nvgpu_log(g, gpu_dbg_fn, "tsg: %s", dev_name(dev));

	priv = nvgpu_kmalloc(g, sizeof(*priv));
	if (!priv) {
		err = -ENOMEM;
		goto free_ref;
	}

	if (!open_share) {
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g, "failed to power on, %d", err);
			goto free_mem;
		}

		tsg = nvgpu_tsg_open(g, nvgpu_current_pid(g));
		gk20a_idle(g);
		if (tsg == NULL) {
			err = -ENOMEM;
			goto free_mem;
		}

		gk20a_sched_ctrl_tsg_added(g, tsg);

#ifndef CONFIG_NVGPU_TSG_SHARING
	}
#else
	} else {
		tsg = nvgpu_gpu_open_tsg_with_share_token(g,
				 source_device_instance_id,
				 target_device_instance_id,
				 share_token);
		if (tsg == NULL) {
			nvgpu_err(g, "TSG open with token failed");
			err = -EINVAL;
			goto free_mem;
		}
	}

	if (ctrl_priv != NULL) {
		err = nvgpu_tsg_add_ctrl_dev_inst_id(tsg, ctrl_priv);
		if (err != 0) {
			nvgpu_err(g, "add ctrl dev failed %d", err);
			nvgpu_ref_put(&tsg->refcount, nvgpu_tsg_release);
			goto free_mem;
		}
	}
#endif

	priv->g = g;
	priv->tsg = tsg;
	priv->cdev = cdev;

	if (ctrl_priv != NULL) {
		nvgpu_ref_get(&ctrl_priv->refcount);
	}
	priv->ctrl_priv = ctrl_priv;

	filp->private_data = priv;

	return 0;

free_mem:
	nvgpu_kfree(g, priv);
free_ref:
	nvgpu_put(g);
	return err;
}

int nvgpu_ioctl_tsg_dev_open(struct inode *inode, struct file *filp)
{
	struct gk20a *g;
	int ret;
	struct nvgpu_cdev *cdev;

	cdev = container_of(inode->i_cdev, struct nvgpu_cdev, cdev);
	g = nvgpu_get_gk20a_from_cdev(cdev);

	nvgpu_log_fn(g, " ");

	ret = gk20a_busy(g);
	if (ret) {
		nvgpu_err(g, "failed to power on, %d", ret);
		return ret;
	}

	ret = nvgpu_ioctl_tsg_open(g, NULL, cdev, filp, false,
				   0ULL, 0ULL, 0ULL);

	gk20a_idle(g);
	nvgpu_log_fn(g, "done");
	return ret;
}

void nvgpu_ioctl_tsg_release(struct nvgpu_ref *ref)
{
	struct nvgpu_tsg *tsg = container_of(ref, struct nvgpu_tsg, refcount);
	struct gk20a *g = tsg->g;

#ifdef CONFIG_NVGPU_TSG_SHARING
	nvgpu_assert(tsg->share_token_count <= 1U);
#endif

	gk20a_sched_ctrl_tsg_removed(g, tsg);

	nvgpu_tsg_release(ref);
}

int nvgpu_ioctl_tsg_dev_release(struct inode *inode, struct file *filp)
{
	struct tsg_private *priv = filp->private_data;
	struct nvgpu_tsg *tsg;
	struct gk20a *g;
#ifdef CONFIG_NVGPU_TSG_SHARING
	u32 count;
	int err;
#endif

	if (!priv) {
		/* open failed, never got a tsg for this file */
		return 0;
	}

	tsg = priv->tsg;
	g = tsg->g;

#ifdef CONFIG_NVGPU_TSG_SHARING
	if (priv->ctrl_priv) {
		nvgpu_mutex_acquire(&tsg->tsg_share_lock);

		err = nvgpu_gpu_tsg_revoke_share_tokens(g,
			nvgpu_gpu_get_device_instance_id(priv->ctrl_priv),
			tsg, &count);
		if (err != 0) {
			nvgpu_err(g, "revoke token(%llu) failed %d",
				  nvgpu_gpu_get_device_instance_id(priv->ctrl_priv),
				  err);
		}

		tsg->share_token_count -= count;

		nvgpu_mutex_release(&tsg->tsg_share_lock);

		nvgpu_tsg_remove_ctrl_dev_inst_id(tsg, priv->ctrl_priv);
	}
#endif

	nvgpu_ref_put(&tsg->refcount, nvgpu_ioctl_tsg_release);
	if (priv->ctrl_priv) {
		nvgpu_ref_put(&priv->ctrl_priv->refcount, nvgpu_ioctl_ctrl_release);
	}
	nvgpu_kfree(g, priv);

	nvgpu_put(g);

	return 0;
}

static int gk20a_tsg_ioctl_set_runlist_interleave(struct gk20a *g,
	struct nvgpu_tsg *tsg, struct nvgpu_runlist_interleave_args *arg)
{
	struct nvgpu_sched_ctrl *sched = &g->sched_ctrl;
	u32 level = arg->level;
	int err;

	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_sched, "tsgid=%u", tsg->tsgid);

	nvgpu_mutex_acquire(&sched->control_lock);
	if (sched->control_locked) {
		err = -EPERM;
		goto done;
	}
	err = gk20a_busy(g);
	if (err) {
		nvgpu_err(g, "failed to power on gpu");
		goto done;
	}

	level = nvgpu_get_common_runlist_level(level);
	err = nvgpu_tsg_set_interleave(tsg, level);

	gk20a_idle(g);
done:
	nvgpu_mutex_release(&sched->control_lock);
	return err;
}

static int gk20a_tsg_ioctl_set_timeslice(struct gk20a *g,
	struct nvgpu_tsg *tsg, struct nvgpu_timeslice_args *arg)
{
	struct nvgpu_sched_ctrl *sched = &g->sched_ctrl;
	int err;

	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_sched, "tsgid=%u", tsg->tsgid);

	nvgpu_mutex_acquire(&sched->control_lock);
	if (sched->control_locked) {
		err = -EPERM;
		goto done;
	}
	err = gk20a_busy(g);
	if (err) {
		nvgpu_err(g, "failed to power on gpu");
		goto done;
	}
	err = g->ops.tsg.set_timeslice(tsg, arg->timeslice_us);
	gk20a_idle(g);
done:
	nvgpu_mutex_release(&sched->control_lock);
	return err;
}

static int gk20a_tsg_ioctl_get_timeslice(struct gk20a *g,
	struct nvgpu_tsg *tsg, struct nvgpu_timeslice_args *arg)
{
	arg->timeslice_us = nvgpu_tsg_get_timeslice(tsg);
	return 0;
}

static int gk20a_tsg_ioctl_read_single_sm_error_state(struct gk20a *g,
		u32 gpu_instance_id,
		struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_read_single_sm_error_state_args *args)
{
	const struct nvgpu_tsg_sm_error_state *sm_error_state = NULL;
	struct nvgpu_tsg_sm_error_state_record sm_error_state_record;
	u32 sm_id;
	int err = 0;

	sm_id = args->sm_id;

	nvgpu_speculation_barrier();

	sm_error_state = nvgpu_tsg_get_sm_error_state(tsg, sm_id);
	if (sm_error_state == NULL) {
		return -EINVAL;
	}

	sm_error_state_record.global_esr =
		sm_error_state->hww_global_esr;
	sm_error_state_record.warp_esr =
		sm_error_state->hww_warp_esr;
	sm_error_state_record.warp_esr_pc =
		sm_error_state->hww_warp_esr_pc;
	sm_error_state_record.global_esr_report_mask =
		sm_error_state->hww_global_esr_report_mask;
	sm_error_state_record.warp_esr_report_mask =
		sm_error_state->hww_warp_esr_report_mask;

	if (args->record_size > 0) {
		size_t write_size = sizeof(*sm_error_state);

		nvgpu_speculation_barrier();
		if (write_size > args->record_size)
			write_size = args->record_size;

		nvgpu_mutex_acquire(&g->dbg_sessions_lock);
		err = copy_to_user((void __user *)(uintptr_t)
						args->record_mem,
				   &sm_error_state_record,
				   write_size);
		nvgpu_mutex_release(&g->dbg_sessions_lock);
		if (err) {
			nvgpu_err(g, "copy_to_user failed!");
			return err;
		}

		args->record_size = write_size;
	}

	return 0;
}

static int nvgpu_gpu_ioctl_set_l2_max_ways_evict_last(
		struct gk20a *g, u32 gpu_instance_id, struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_l2_max_ways_evict_last_args *args)
{
	int err;
	u32 gr_instance_id =
		nvgpu_grmgr_get_gr_instance_id(g, gpu_instance_id);

	nvgpu_mutex_acquire(&g->dbg_sessions_lock);
	if (g->ops.ltc.set_l2_max_ways_evict_last) {
		err = nvgpu_gr_exec_with_err_for_instance(g, gr_instance_id,
				g->ops.ltc.set_l2_max_ways_evict_last(g, tsg,
					args->max_ways));
	} else {
		err = -ENOSYS;
	}
	nvgpu_mutex_release(&g->dbg_sessions_lock);

	return err;
}

static int nvgpu_gpu_ioctl_get_l2_max_ways_evict_last(
		struct gk20a *g, u32 gpu_instance_id, struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_l2_max_ways_evict_last_args *args)
{
	int err;
	u32 gr_instance_id =
		nvgpu_grmgr_get_gr_instance_id(g, gpu_instance_id);

	nvgpu_mutex_acquire(&g->dbg_sessions_lock);
	if (g->ops.ltc.get_l2_max_ways_evict_last) {
		err = nvgpu_gr_exec_with_err_for_instance(g, gr_instance_id,
				g->ops.ltc.get_l2_max_ways_evict_last(g, tsg,
					&args->max_ways));
	} else {
		err = -ENOSYS;
	}
	nvgpu_mutex_release(&g->dbg_sessions_lock);

	return err;
}

static u32 nvgpu_translate_l2_sector_promotion_flag(struct gk20a *g, u32 flag)
{
	u32 promotion_flag = NVGPU_L2_SECTOR_PROMOTE_FLAG_INVALID;

	switch (flag) {
		case NVGPU_GPU_IOCTL_TSG_L2_SECTOR_PROMOTE_FLAG_NONE:
			promotion_flag = NVGPU_L2_SECTOR_PROMOTE_FLAG_NONE;
			break;

		case NVGPU_GPU_IOCTL_TSG_L2_SECTOR_PROMOTE_FLAG_64B:
			promotion_flag = NVGPU_L2_SECTOR_PROMOTE_FLAG_64B;
			break;

		case NVGPU_GPU_IOCTL_TSG_L2_SECTOR_PROMOTE_FLAG_128B:
			promotion_flag = NVGPU_L2_SECTOR_PROMOTE_FLAG_128B;
			break;

		default:
			nvgpu_err(g, "invalid sector promotion flag(%d)",
					flag);
			break;
	}

	return promotion_flag;
}

static int nvgpu_gpu_ioctl_set_l2_sector_promotion(struct gk20a *g,
		u32 gpu_instance_id, struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_set_l2_sector_promotion_args *args)
{
	u32 promotion_flag = 0U;
	int err = 0;
	u32 gr_instance_id =
		nvgpu_grmgr_get_gr_instance_id(g, gpu_instance_id);

	/*
	 * L2 sector promotion is a perf feature so return silently without
	 * error if not supported.
	 */
	if (g->ops.ltc.set_l2_sector_promotion == NULL) {
		return 0;
	}

	promotion_flag =
		nvgpu_translate_l2_sector_promotion_flag(g,
				args->promotion_flag);
	if (promotion_flag ==
			NVGPU_L2_SECTOR_PROMOTE_FLAG_INVALID) {
		return -EINVAL;
	}

	err = gk20a_busy(g);
	if (err) {
		nvgpu_err(g, "failed to power on gpu");
		return err;
	}
	err = nvgpu_gr_exec_with_err_for_instance(g, gr_instance_id,
			g->ops.ltc.set_l2_sector_promotion(g, tsg,
				promotion_flag));
	gk20a_idle(g);

	return err;
}

static int nvgpu_tsg_ioctl_create_subcontext(struct gk20a *g,
		u32 gpu_instance_id, struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_create_subcontext_args *args)
{
	u32 max_subctx_count;
	struct vm_gk20a *vm;
	u32 veid;
	int err;

	if (!nvgpu_is_enabled(g, NVGPU_SUPPORT_TSG_SUBCONTEXTS)) {
		return 0;
	}

	if (args->type != NVGPU_TSG_SUBCONTEXT_TYPE_SYNC &&
	    args->type != NVGPU_TSG_SUBCONTEXT_TYPE_ASYNC) {
		nvgpu_err(g, "Invalid subcontext type %u", args->type);
		return -EINVAL;
	}

	vm = nvgpu_vm_get_from_file(args->as_fd);
	if (vm == NULL) {
		nvgpu_err(g, "Invalid VM (fd = %d) specified for subcontext",
			  args->as_fd);
		return -EINVAL;
	}

	max_subctx_count = nvgpu_grmgr_get_gpu_instance_max_veid_count(g, gpu_instance_id);

	err = nvgpu_tsg_create_subcontext(g, tsg, args->type, vm,
					  max_subctx_count, &veid);
	if (err != 0) {
		nvgpu_err(g, "Create subcontext failed %d", err);
		nvgpu_vm_put(vm);
		return err;
	}

	nvgpu_vm_put(vm);

	args->veid = veid;

	return 0;
}

static int nvgpu_tsg_ioctl_delete_subcontext(struct gk20a *g,
		u32 gpu_instance_id, struct nvgpu_tsg *tsg,
		struct nvgpu_tsg_delete_subcontext_args *args)
{
	u32 max_subctx_count;
	int err;

	if (!nvgpu_is_enabled(g, NVGPU_SUPPORT_TSG_SUBCONTEXTS)) {
		return 0;
	}

	max_subctx_count = nvgpu_grmgr_get_gpu_instance_max_veid_count(g, gpu_instance_id);

	err = nvgpu_tsg_user_delete_subcontext(g, tsg, max_subctx_count,
					       args->veid);
	if (err != 0) {
		nvgpu_err(g, "Delete subcontext failed %d", err);
	}

	return err;
}

long nvgpu_ioctl_tsg_dev_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long arg)
{
	struct tsg_private *priv = filp->private_data;
	struct nvgpu_tsg *tsg = priv->tsg;
	struct gk20a *g = tsg->g;
	u8 __maybe_unused buf[NVGPU_TSG_IOCTL_MAX_ARG_SIZE];
	int err = 0;
	u32 gpu_instance_id, gr_instance_id;

	nvgpu_log_fn(g, "start %d", _IOC_NR(cmd));

	if ((_IOC_TYPE(cmd) != NVGPU_TSG_IOCTL_MAGIC) ||
	    (_IOC_NR(cmd) == 0) ||
	    (_IOC_NR(cmd) > NVGPU_TSG_IOCTL_LAST) ||
	    (_IOC_SIZE(cmd) > NVGPU_TSG_IOCTL_MAX_ARG_SIZE))
		return -EINVAL;

	(void) memset(buf, 0, sizeof(buf));
	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		if (copy_from_user(buf, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	if (!g->sw_ready) {
		err = gk20a_busy(g);
		if (err)
			return err;

		gk20a_idle(g);
	}

	gpu_instance_id = nvgpu_get_gpu_instance_id_from_cdev(g, priv->cdev);
	nvgpu_assert(gpu_instance_id < g->mig.num_gpu_instances);
	gr_instance_id = nvgpu_grmgr_get_gr_instance_id(g, gpu_instance_id);
	nvgpu_assert(gr_instance_id < g->num_gr_instances);

	switch (cmd) {
	case NVGPU_TSG_IOCTL_BIND_CHANNEL:
		{
		int ch_fd = *(int *)buf;
		if (ch_fd < 0) {
			err = -EINVAL;
			break;
		}
		err = nvgpu_tsg_bind_channel_fd(tsg, ch_fd);
		break;
		}

	case NVGPU_TSG_IOCTL_BIND_CHANNEL_EX:
	{
		err = gk20a_tsg_ioctl_bind_channel_ex(g, priv,
			(struct nvgpu_tsg_bind_channel_ex_args *)buf);
		break;
	}

	case NVGPU_TSG_IOCTL_UNBIND_CHANNEL:
		{
		int ch_fd = *(int *)buf;

		if (ch_fd < 0) {
			err = -EINVAL;
			break;
		}
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to host gk20a for ioctl cmd: 0x%x", cmd);
			break;
		}
		err = nvgpu_tsg_unbind_channel_fd(tsg, ch_fd);
		gk20a_idle(g);
		break;
		}

#ifdef CONFIG_NVS_PRESENT
	case NVGPU_TSG_IOCTL_BIND_SCHEDULING_DOMAIN:
		{
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to host gk20a for ioctl cmd: 0x%x", cmd);
			break;
		}
		err = nvgpu_tsg_bind_scheduling_domain(tsg,
				(struct nvgpu_tsg_bind_scheduling_domain_args *)buf);
		gk20a_idle(g);
		break;
		}
#endif

	case NVGPU_IOCTL_TSG_ENABLE:
		{
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to host gk20a for ioctl cmd: 0x%x", cmd);
			return err;
		}
		g->ops.tsg.enable(tsg);
		gk20a_idle(g);
		break;
		}

	case NVGPU_IOCTL_TSG_DISABLE:
		{
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to host gk20a for ioctl cmd: 0x%x", cmd);
			return err;
		}
		g->ops.tsg.disable(tsg);
		gk20a_idle(g);
		break;
		}

	case NVGPU_IOCTL_TSG_PREEMPT:
		{
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to host gk20a for ioctl cmd: 0x%x", cmd);
			return err;
		}
		/* preempt TSG */
		err = nvgpu_tsg_preempt(g, tsg);
		gk20a_idle(g);
		break;
		}

#ifdef CONFIG_NVGPU_CHANNEL_TSG_CONTROL
	case NVGPU_IOCTL_TSG_EVENT_ID_CTRL:
		{
		err = gk20a_tsg_event_id_ctrl(g, tsg,
			(struct nvgpu_event_id_ctrl_args *)buf);
		break;
		}
#endif

	case NVGPU_IOCTL_TSG_SET_RUNLIST_INTERLEAVE:
		err = gk20a_tsg_ioctl_set_runlist_interleave(g, tsg,
			(struct nvgpu_runlist_interleave_args *)buf);
		break;

	case NVGPU_IOCTL_TSG_SET_TIMESLICE:
		{
		err = gk20a_tsg_ioctl_set_timeslice(g, tsg,
			(struct nvgpu_timeslice_args *)buf);
		break;
		}
	case NVGPU_IOCTL_TSG_GET_TIMESLICE:
		{
		err = gk20a_tsg_ioctl_get_timeslice(g, tsg,
			(struct nvgpu_timeslice_args *)buf);
		break;
		}

	case NVGPU_TSG_IOCTL_READ_SINGLE_SM_ERROR_STATE:
		{
		err = gk20a_tsg_ioctl_read_single_sm_error_state(g, gpu_instance_id, tsg,
			(struct nvgpu_tsg_read_single_sm_error_state_args *)buf);
		break;
		}

	case NVGPU_TSG_IOCTL_SET_L2_MAX_WAYS_EVICT_LAST:
		{
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to power on gpu for ioctl cmd: 0x%x", cmd);
			break;
		}
		err = nvgpu_gpu_ioctl_set_l2_max_ways_evict_last(g,
				gpu_instance_id, tsg,
				(struct nvgpu_tsg_l2_max_ways_evict_last_args *)buf);
		gk20a_idle(g);
		break;
		}

	case NVGPU_TSG_IOCTL_GET_L2_MAX_WAYS_EVICT_LAST:
		{
		err = gk20a_busy(g);
		if (err) {
			nvgpu_err(g,
			   "failed to power on gpu for ioctl cmd: 0x%x", cmd);
			break;
		}
		err = nvgpu_gpu_ioctl_get_l2_max_ways_evict_last(g,
				gpu_instance_id, tsg,
				(struct nvgpu_tsg_l2_max_ways_evict_last_args *)buf);
		gk20a_idle(g);
		break;
		}

	case NVGPU_TSG_IOCTL_SET_L2_SECTOR_PROMOTION:
		{
		err = nvgpu_gpu_ioctl_set_l2_sector_promotion(g,
				gpu_instance_id, tsg,
				(struct nvgpu_tsg_set_l2_sector_promotion_args *)buf);
		break;
		}

	case NVGPU_TSG_IOCTL_CREATE_SUBCONTEXT:
		{
		err = nvgpu_tsg_ioctl_create_subcontext(g, gpu_instance_id, tsg,
				(struct nvgpu_tsg_create_subcontext_args *)buf);
		break;
		}
	case NVGPU_TSG_IOCTL_DELETE_SUBCONTEXT:
		{
		err = nvgpu_tsg_ioctl_delete_subcontext(g, gpu_instance_id, tsg,
				(struct nvgpu_tsg_delete_subcontext_args *)buf);
		break;
		}
#ifdef CONFIG_NVGPU_TSG_SHARING
	case NVGPU_TSG_IOCTL_GET_SHARE_TOKEN:
		{
		err = nvgpu_tsg_ioctl_get_share_token(g, priv,
					(struct nvgpu_tsg_get_share_token_args *)buf);
		break;
		}
	case NVGPU_TSG_IOCTL_REVOKE_SHARE_TOKEN:
		{
		err = nvgpu_tsg_ioctl_revoke_share_token(g, tsg,
					(struct nvgpu_tsg_revoke_share_token_args *)buf);
		break;
		}
#endif
	default:
		nvgpu_err(g, "unrecognized tsg gpu ioctl cmd: 0x%x",
			   cmd);
		err = -ENOTTY;
		break;
	}

	if ((err == 0) && (_IOC_DIR(cmd) & _IOC_READ))
		err = copy_to_user((void __user *)arg,
				   buf, _IOC_SIZE(cmd));

	return err;
}
