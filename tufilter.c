/********************************************************************
 * PROGRAM: tufilter
 * FILE: tufilter.c
 * PURPOSE: filters incoming & outgoing packets, sends current rules
 *          statistics to the host
 * AUTHOR: 5aboteur <5aboteur@protonmail.com>
 *******************************************************************/

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "tufilter.h"

/* --------------------------------------------------------------- */

// Rules table
static rule_t *rules;

// Table`s auxiliary stuff
static uint32_t cur_rules_num;
static uint32_t cur_rules_pos;

// Module essentials
static int __init tufilter_start(void);
static void __exit tufilter_end(void);
static int tufilter_open(struct inode *i, struct file *f);
static int tufilter_release(struct inode *i, struct file *f);
static long tufilter_ioctl(struct file *f, unsigned int cmd,
	unsigned long arg);

// Searches for duplicates in the rules table
static int find_duplicate(rule_t *rule);

// Net hooks stuff
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static unsigned int hook_func_in(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state);
static unsigned int hook_func_out(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state);

// Determines whether a packet should be drop or not
static int packet_drop(unsigned int addr, unsigned short port,
	char *proto, char *route);

// Converts an ip addr from unsigned int into char string
static void uint_to_str_ip(unsigned int addr, char *str);

// Other stuff
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = tufilter_open,
	.release = tufilter_release,
	.unlocked_ioctl = tufilter_ioctl
};

static dev_t dev;
static struct cdev c_dev;

/* --------------------------------------------------------------- */

static int __init tufilter_start(void)
{
	int rval;

	/* Init device stage */

	dev = MKDEV(MAJOR_NUM, MINOR_NUM);

	rval = register_chrdev_region(dev, MINOR_CNT, DEV_NAME);
	if (rval < 0) {
		pr_err("Registering device region failed\n");
		return rval;
	}

	cdev_init(&c_dev, &fops);

	rval = cdev_add(&c_dev, dev, MINOR_CNT);
	if (rval < 0) {
		pr_err("Couldn`t add character device\n");
		unregister_chrdev_region(dev, MINOR_CNT);
		return rval;
	}

	/* Init a hook for incoming packets */

	nfho_in.hook = hook_func_in;
	nfho_in.hooknum = NF_INET_LOCAL_IN;
	nfho_in.pf = PF_INET;
	nfho_in.priority = NF_IP_PRI_FIRST;

	rval = nf_register_net_hook(&init_net, &nfho_in);
	if (rval < 0) {
		pr_err("Couldn`t register incoming packets hook\n");
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return rval;
	}

	/* Init another hook for outgoing packets */

	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;

	rval = nf_register_net_hook(&init_net, &nfho_out);
	if (rval < 0) {
		pr_err("Couldn`t register outgoing packets hook\n");
		nf_unregister_net_hook(&init_net, &nfho_in);
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return rval;
	}

	rules = kmalloc(sizeof(rule_t) * MAX_RULES_NUM, GFP_KERNEL);

	pr_info("Module '%s' successfully loaded\n", DEV_NAME);

	return rval;
}

static void __exit tufilter_end(void)
{
	kfree(rules);

	nf_unregister_net_hook(&init_net, &nfho_in);
	nf_unregister_net_hook(&init_net, &nfho_out);

	cdev_del(&c_dev);
	unregister_chrdev_region(dev, MINOR_CNT);

	pr_info("Module '%s' successfully unloaded\n", DEV_NAME);
}

/* --------------------------------------------------------------- */

static int tufilter_open(struct inode *i, struct file *f)
{
	pr_info(">>>\n");
	return 0;
}

static int tufilter_release(struct inode *i, struct file *f)
{
	pr_info("<<<\n");
	return 0;
}

static long tufilter_ioctl(struct file *f, unsigned int cmd,
	unsigned long arg)
{
	rule_t rule;
	int rval;

	switch (cmd) {
		case IOCTL_CLR_BUF_POS:
			cur_rules_pos = 0;
			break;
		case IOCTL_GET_RULES_NUM:
			rval = copy_to_user((uint32_t *) arg, &cur_rules_num,
				sizeof(uint32_t));
			if (rval < 0) {
				pr_err("Couldn`t send current number of rules\n");
				kfree(rules);
				return rval;
			}
			pr_info("Rules number (%u) sent\n", cur_rules_num);
			break;
		case IOCTL_GET_RULE:
			/* Gets another rule from the table and sends it
				to the user space */
			strcpy(rule.ip_addr, rules[cur_rules_pos].ip_addr);
			rule.port = rules[cur_rules_pos].port;
			rule.flags = rules[cur_rules_pos].flags;

			rval = copy_to_user((rule_t *) arg, &rule, sizeof(rule_t));
			if (rval < 0) {
				pr_err("Couldn`t send current number of rules\n");
				kfree(rules);
				return rval;
			}
			pr_info("Rule #%u sent\n", cur_rules_pos);
			cur_rules_pos++;
			break;
		case IOCTL_SET_RULE:
			rval = copy_from_user(&rule, (rule_t *) arg,
				sizeof(rule_t));
			if (rval < 0) {
				pr_err("Couldn`t copy data from user\n");
				kfree(rules);
				return rval;
			}

			if (!find_duplicate(&rule)) {
				/* This rule is not the duplicate one, add it */
				strcpy(rules[cur_rules_num].ip_addr, rule.ip_addr);
				rules[cur_rules_num].port = rule.port;
				rules[cur_rules_num].flags = rule.flags;

				pr_info("New rule added\n");
				cur_rules_num++;
			}
			break;
		default:
			return -EINVAL;
	}

	return 0;
}

static int find_duplicate(rule_t *rule)
{
	int i;
	size_t sz;

	for (i = 0; i < cur_rules_num; ++i) {
		if (!(strcmp(rules[i].ip_addr, rule->ip_addr)) &&
			(rules[i].port == rule->port) &&
			(!(strcmp(GET_PROTO(rules[i]), GET_PROTO((*rule))))) &&
			(!(strcmp(GET_ROUTE(rules[i]), GET_ROUTE((*rule)))))) {
			/* If filter is set to disable mode, then we need to
				disable this rule, otherwise it`s a duplicate */
			if (!GET_FILTER((*rule))) {
				if (i + 1 < cur_rules_num) {
					sz = (sizeof(rule_t) * (cur_rules_num - i));
					// Shift over the top of rm`d rule
					memmove(&rules[i], &rules[i + 1], sz);
					pr_info("%zu bytes moved from [%d] to [%d]\n",
						sz, i + 1, i);
				}
				cur_rules_num--;
				return 1;
			}
			else {
				pr_info("Duplicate found at [%d], skipped\n", i);
				return 1;
			}
		}
	}

	return 0;
}

/* --------------------------------------------------------------- */

static unsigned int hook_func_in(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	uint32_t s_addr;
	uint16_t d_port;

	char ip_addr[MAX_IP_ADDR_LEN];

	if (!skb) {
		return NF_ACCEPT;
	}

	iph = (struct iphdr *) skb_network_header(skb);
	s_addr = iph->saddr;

	uint_to_str_ip(s_addr, ip_addr);

	pr_info("packet arrived from '%s'\n", ip_addr);

	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));
			if (!tcph) {
				return NF_ACCEPT;
			}

			d_port= tcph->dest;

			pr_info(" on port '%hu' TCP\n", ntohs(d_port));

			if (packet_drop(s_addr, d_port, "TCP", "IN")) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));
			if (!udph) {
				return NF_ACCEPT;
			}

			d_port = udph->dest;

			pr_info(" on port '%hu' UDP\n", ntohs(d_port));

			if (packet_drop(s_addr, d_port, "UDP", "IN")) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
	}

	return NF_ACCEPT;
}

static unsigned int hook_func_out(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	uint32_t d_addr;
	uint16_t s_port;

	char ip_addr[MAX_IP_ADDR_LEN];

	if (!skb) {
		return NF_ACCEPT;
	}

	iph = (struct iphdr *) skb_network_header(skb);
	d_addr = iph->daddr;

	uint_to_str_ip(d_addr, ip_addr);

	pr_info("packet sent to '%s'\n", ip_addr);

	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));
			if (!tcph) {
				return NF_ACCEPT;
			}

			s_port= tcph->source;

			pr_info(" from port '%hu' TCP\n", ntohs(s_port));

			if (packet_drop(d_addr, s_port, "TCP", "OUT")) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));
			if (!udph) {
				return NF_ACCEPT;
			}

			s_port = udph->source;

			pr_info(" from port '%hu' UDP\n", ntohs(s_port));

			if (packet_drop(d_addr, s_port, "UDP", "OUT")) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
	}

	return NF_ACCEPT;
}

static int packet_drop(unsigned int addr, unsigned short port,
	char *proto, char *route)
{
	int i;
	char ip_addr[MAX_IP_ADDR_LEN];

	uint_to_str_ip(addr, ip_addr);

	for (i = 0; i < cur_rules_num; ++i) {
		// Ooh, that`s a sexy one condition!
		if ((((!(strcmp(rules[i].ip_addr, "N/A"))) &&
			(rules[i].port == port)) ||
			((!(strcmp(rules[i].ip_addr, ip_addr))) &&
			(rules[i].port == 0)) ||
			((!(strcmp(rules[i].ip_addr, ip_addr))) &&
			(rules[i].port == port))) &&
			((!(strcmp(GET_PROTO(rules[i]), proto))) &&
			(!(strcmp(GET_ROUTE(rules[i]), route))))) {
			return 1;
		}
	}

	return 0;
}

static void uint_to_str_ip(unsigned int addr, char *str)
{
	snprintf(str, sizeof(char) * MAX_IP_ADDR_LEN, "%u.%u.%u.%u",
		(addr & 0x000000ff), (addr & 0x0000ff00) >> 8,
		(addr & 0x00ff0000) >> 16, (addr & 0xff000000) >> 24);
}

/* --------------------------------------------------------------- */

module_init(tufilter_start);
module_exit(tufilter_end);

MODULE_AUTHOR("5aboteur <5aboteur@protonmail.com");
MODULE_DESCRIPTION("Filters incoming & outgoing packets");
MODULE_LICENSE("GPL");
