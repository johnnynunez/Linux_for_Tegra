/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/platform/tegra/ptp-notifier.h>

static int (*get_systime[MAX_MAC_INSTANCES])(struct net_device *, void *, int);
static struct net_device *registered_ndev[MAX_MAC_INSTANCES];
static DEFINE_RAW_SPINLOCK(ptp_notifier_lock);
static ATOMIC_NOTIFIER_HEAD(tegra_hwtime_chain_head);

/* Clients register for notification of hwtime change events */
int tegra_register_hwtime_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&tegra_hwtime_chain_head, nb);
}
EXPORT_SYMBOL(tegra_register_hwtime_notifier);

/* Clients unregister for notification of hwtime change events */
int tegra_unregister_hwtime_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&tegra_hwtime_chain_head, nb);
}
EXPORT_SYMBOL(tegra_unregister_hwtime_notifier);

/* Trigger notification of hwtime change to all registered clients */
int tegra_hwtime_notifier_call_chain(unsigned int val, void *v)
{
	int ret = atomic_notifier_call_chain(&tegra_hwtime_chain_head, val, v);

	return notifier_to_errno(ret);
}

void tegra_register_hwtime_source(int (*func)(struct net_device *, void *, int),
				  struct net_device *ndev)
{
	unsigned long flags;
	int index = 0;

	for (index = 0; index < MAX_MAC_INSTANCES; index++) {
		if (registered_ndev[index] == ndev) {
			pr_debug("source is already registered for this intf\n");
			/* Didn't call the notifier as we are not using
			 * tegra_register_hwtime_notifier anywhere
			 */
			return;
		}
	}
	raw_spin_lock_irqsave(&ptp_notifier_lock, flags);
	for (index = 0; index < MAX_MAC_INSTANCES; index++) {
		if (get_systime[index] == NULL) {
			get_systime[index] = func;
			registered_ndev[index] = ndev;
			break;
		}
	}
	if (index ==  MAX_MAC_INSTANCES)
		pr_err("Maximum registrations reached\n");

	raw_spin_unlock_irqrestore(&ptp_notifier_lock, flags);

	/* Notify HW time stamp update to registered clients.
	 * NULL callback parameter. We use a separate timestamp
	 * function to peek MAC time.
	 */
	tegra_hwtime_notifier_call_chain(0, NULL);
}
EXPORT_SYMBOL(tegra_register_hwtime_source);

void tegra_unregister_hwtime_source(struct net_device *dev)
{
	unsigned long flags;
	int index = 0;

	raw_spin_lock_irqsave(&ptp_notifier_lock, flags);
	for (index = 0; index < MAX_MAC_INSTANCES; index++) {
		if (dev == registered_ndev[index])
			break;
	}
	if (index == MAX_MAC_INSTANCES) {
		pr_debug("Trying to unregister non-registered hwtime source");
		raw_spin_unlock_irqrestore(&ptp_notifier_lock, flags);
		return;
	}
	get_systime[index] = NULL;
	registered_ndev[index] = NULL;
	raw_spin_unlock_irqrestore(&ptp_notifier_lock, flags);
}
EXPORT_SYMBOL(tegra_unregister_hwtime_source);

int tegra_get_hwtime(const char *intf_name, void *ts, int ts_type)
{
	unsigned long flags;
	int ret = 0, index = 0;
	struct net_device *dev;

	raw_spin_lock_irqsave(&ptp_notifier_lock, flags);
	if (!intf_name || !ts) {
		pr_err("passed Interface_name or time-stamp ptr is NULL");
		raw_spin_unlock_irqrestore(&ptp_notifier_lock, flags);
		return -1;
	}
	dev = dev_get_by_name(&init_net, intf_name);

	if (!dev || !(dev->flags & IFF_UP)) {
		pr_debug("dev is NULL or intf is not up for %s\n", intf_name);
		ret = -EINVAL;
		goto out;
	}
	for (index = 0; index < MAX_MAC_INSTANCES; index++) {
		if (dev == registered_ndev[index])
			break;
	}
	if (index == MAX_MAC_INSTANCES) {
		pr_debug("Interface: %s is not registered to get HW time", intf_name);
		ret = -EINVAL;
		goto out;
	}

	if (get_systime[index])
		ret = (get_systime[index])(dev, ts, ts_type);
	else
		ret = -EINVAL;

out:
	if (dev)
		dev_put(dev);
	raw_spin_unlock_irqrestore(&ptp_notifier_lock, flags);

	return ret;
}
EXPORT_SYMBOL(tegra_get_hwtime);

MODULE_LICENSE("GPL");
