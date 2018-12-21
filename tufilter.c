/********************************************************************
 * PROGRAM: tufilter
 * FILE: tufilter.c
 * PURPOSE: filters incoming & outgoing packets, sends current rules
 *          statistics to the host
 * AUTHOR: 5aboteur <5aboteur@protonmail.com>
 *******************************************************************/

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
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
static ssize_t tufilter_read(struct file *f, char __user *buf,
	size_t sz, loff_t *off);
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
	unsigned char proto, unsigned char route);

// Converts an ip addr from unsigned int to char string
static void uint_to_str_ip(unsigned int addr, char *str);

// Device stuff
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = tufilter_open,
	.release = tufilter_release,
	.read = tufilter_read,
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

	/* Init proc stage */

	proc_create(DEV_NAME, S_IFREG | S_IRUSR, NULL, &fops);

	/* Init a hook for incoming packets */

	nfho_in.hook = hook_func_in;
	nfho_in.hooknum = NF_INET_PRE_ROUTING;
	nfho_in.pf = PF_INET;
	nfho_in.priority = NF_IP_PRI_FIRST;

	rval = nf_register_net_hook(&init_net, &nfho_in);
	if (rval < 0) {
		pr_err("Couldn`t register incoming packets hook\n");
		remove_proc_entry(DEV_NAME, NULL);
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return rval;
	}

	/* Init another hook for outgoing packets */

	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_POST_ROUTING;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;

	rval = nf_register_net_hook(&init_net, &nfho_out);
	if (rval < 0) {
		pr_err("Couldn`t register outgoing packets hook\n");
		nf_unregister_net_hook(&init_net, &nfho_in);
		remove_proc_entry(DEV_NAME, NULL);
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return rval;
	}

	rules = kmalloc(sizeof(rule_t) * MAX_RULES_NUM, GFP_KERNEL);

	if (!rules) {
		nf_unregister_net_hook(&init_net, &nfho_in);
		nf_unregister_net_hook(&init_net, &nfho_out);
		remove_proc_entry(DEV_NAME, NULL);
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return -ENOMEM;
	}

	pr_info("Module '%s' successfully loaded\n", DEV_NAME);

	return rval;
}

static void __exit tufilter_end(void)
{
	kfree(rules);

	nf_unregister_net_hook(&init_net, &nfho_in);
	nf_unregister_net_hook(&init_net, &nfho_out);

	remove_proc_entry(DEV_NAME, NULL);

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

static ssize_t tufilter_read(struct file *f, char __user *buf,
	size_t sz, loff_t *off)
{
	char *kbuf, *rule_stat;
	unsigned i;
	unsigned long rval, rbytes;
	size_t kbuf_len;

	/* Nuffin' to do */
	if (cur_rules_num == 0 || sz == 0 || *off != 0) {
		return 0;
	}

	if (!buf) {
		pr_err("User buffer points to NULL\n");
		return -EBADMSG;
	}

	kbuf = kzalloc(sizeof(char) * cur_rules_num *
		MAX_RULE_STRLEN, GFP_KERNEL);

	if (!kbuf) {
		return -ENOMEM;
	}

	rule_stat = kmalloc(sizeof(char) * MAX_RULE_STRLEN,
		GFP_KERNEL);

	if (!rule_stat) {
		kfree(kbuf);
		return -ENOMEM;
	}

	for (i = 0; i < cur_rules_num; ++i) {
		sprintf(rule_stat, "rule #%u: %u packets dropped\n",
			i + 1, rules[i].drop_cnt);
		strcat(kbuf, rule_stat);
	}

	kfree(rule_stat);

	kbuf_len = strlen(kbuf);
	rbytes = (kbuf_len < sz) ? kbuf_len : sz;

	rval = copy_to_user(buf, kbuf, rbytes);
	if (rval > 0) {
		pr_err("Failed to copy data to userspace\n");
		kfree(kbuf);
		return -EFAULT;
	}

	*off = rbytes;

	pr_info("%lu bytes read, returned msg from <%s>:\n%s\n",
		rbytes, DEV_NAME, kbuf);

	kfree(kbuf);

	return rbytes;
}

static long tufilter_ioctl(struct file *f, unsigned int cmd,
	unsigned long arg)
{
	rule_t rule;
	unsigned long rval;

	switch (cmd) {
		case IOCTL_TABLE_ZPOS:
			cur_rules_pos = 0;
			break;
		case IOCTL_GET_RULES_NUM:
			rval = copy_to_user((uint32_t *) arg, &cur_rules_num,
				sizeof(uint32_t));
			if (rval > 0) {
				pr_err("Couldn`t send current number of rules\n");
				return -EFAULT;
			}
			pr_info("Rules number (%u) sent\n", cur_rules_num);
			break;
		case IOCTL_GET_RULE:
			/* If we reach the table threshold, then goto
				its first element */
			if (cur_rules_pos >= MAX_RULES_NUM) {
				cur_rules_pos = 0;
			}

			/* Get another rule from the table and send it
				to the user space */
			rule.drop_cnt = rules[cur_rules_pos].drop_cnt;
			rule.ip_addr = rules[cur_rules_pos].ip_addr;
			rule.port = rules[cur_rules_pos].port;
			rule.proto = rules[cur_rules_pos].proto;
			rule.flags = rules[cur_rules_pos].flags;

			rval = copy_to_user((rule_t *) arg, &rule, sizeof(rule_t));
			if (rval > 0) {
				pr_err("Couldn`t send rule #%u\n", cur_rules_pos + 1);
				return -EFAULT;
			}

			cur_rules_pos++;

			pr_info("Rule #%u sent <%u,%hu,%u,%u,%u>\n",
				cur_rules_pos, rule.ip_addr, rule.port,
				rule.proto, rule.flags, rule.drop_cnt);
			break;
		case IOCTL_SET_RULE:
			rval = copy_from_user(&rule, (rule_t *) arg,
				sizeof(rule_t));
			if (rval > 0) {
				pr_err("Couldn`t copy data from user\n");
				return -EFAULT;
			}

			/* If the rule is not a duplicate, the filter is
				enabled and the table isn`t full -> add */
			if ((!find_duplicate(&rule)) && (GET_FILTER(rule)) &&
				(cur_rules_num < MAX_RULES_NUM)) {
				rules[cur_rules_num].drop_cnt = rule.drop_cnt;
				rules[cur_rules_num].ip_addr = rule.ip_addr;
				rules[cur_rules_num].port = rule.port;
				rules[cur_rules_num].proto = rule.proto;
				rules[cur_rules_num].flags = rule.flags;

				cur_rules_num++;

				pr_info("Rule #%u added <%u,%hu,%u,%u,%u>\n",
					cur_rules_num, rule.ip_addr, rule.port,
					rule.proto, rule.flags, rule.drop_cnt);
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
		if ((rules[i].ip_addr == rule->ip_addr) &&
			(rules[i].port == rule->port) &&
			(rules[i].proto == rule->proto) &&
			(((GET_ROUTE(rules[i])) == (GET_ROUTE((*rule)))))) {
			/* If filter is set to disable mode, then we need to
				disable this rule, otherwise it`s a duplicate */
			if (!GET_FILTER((*rule))) {
				if (i + 1 < cur_rules_num) {
					sz = (sizeof(rule_t) * (cur_rules_num - i - 1));
					// Shift over the top of rm`d rule
					memmove(&rules[i], &rules[i + 1], sz);
					pr_info("%zu bytes moved from [%d] to [%d]\n",
						sz, // full sz of shifted data
						i + 2, // i + 1 (off) + 1 (table idx)
						i + 1); // i + 1 (table idx)
				}
				cur_rules_num--;
				return 1;
			}
			else {
				pr_info("Duplicate found at [%d], skipped\n", i + 1);
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

	char ip_addr[INET_ADDRSTRLEN];

	if (!skb) {
		return NF_ACCEPT;
	}

	iph = (struct iphdr *) skb_network_header(skb);
	s_addr = ntohl(iph->saddr);

	uint_to_str_ip(s_addr, ip_addr);

	pr_info("packet arrived from '%s'\n", ip_addr);

	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));

			d_port = ntohs(tcph->dest);

			pr_info(" on TCP port '%hu'\n", d_port);

			if (packet_drop(s_addr, d_port, IPPROTO_TCP, ROUTE_IN)) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));

			d_port = ntohs(udph->dest);

			pr_info(" on UDP port '%hu'\n", d_port);

			if (packet_drop(s_addr, d_port, IPPROTO_UDP, ROUTE_IN)) {
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

	char ip_addr[INET_ADDRSTRLEN];

	if (!skb) {
		return NF_ACCEPT;
	}

	iph = (struct iphdr *) skb_network_header(skb);
	d_addr = ntohl(iph->daddr);

	uint_to_str_ip(d_addr, ip_addr);

	pr_info("packet sent to '%s'\n", ip_addr);

	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));

			s_port = ntohs(tcph->source);

			pr_info(" from TCP port '%hu'\n", s_port);

			if (packet_drop(d_addr, s_port, IPPROTO_TCP, ROUTE_OUT)) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *) (skb_transport_header(skb) +
				ip_hdrlen(skb));

			s_port = ntohs(udph->source);

			pr_info(" from UDP port '%hu'\n", s_port);

			if (packet_drop(d_addr, s_port, IPPROTO_UDP, ROUTE_OUT)) {
				pr_info(" ~> packet dropped\n");
				return NF_DROP;
			}
			break;
	}

	return NF_ACCEPT;
}

static int packet_drop(unsigned int addr, unsigned short port,
	unsigned char proto, unsigned char route)
{
	int i;

	for (i = 0; i < cur_rules_num; ++i) {
		/* If (ips are equal and port isn`t specified OR
			ports are equal and ip isn`t specified OR
			both ips and ports are equal) AND
			(protos and routes are the same) then TRUE */
		if ((((rules[i].ip_addr == 0) &&
			(rules[i].port == port)) ||
			((rules[i].ip_addr == addr) &&
			(rules[i].port == 0)) ||
			((rules[i].ip_addr == addr) &&
			(rules[i].port == port))) &&
			((rules[i].proto == proto) &&
			((!(GET_ROUTE(rules[i]) ^ route))))) {
			rules[i].drop_cnt++;
			return 1;
		}
	}

	return 0;
}

static void uint_to_str_ip(unsigned int addr, char *str)
{
	snprintf(str, sizeof(char) * INET_ADDRSTRLEN, "%u.%u.%u.%u",
		((addr >> 24) & 0xFF), ((addr >> 16) & 0xFF),
		((addr >> 8) & 0xFF), (addr & 0xFF));
}

/* --------------------------------------------------------------- */

module_init(tufilter_start);
module_exit(tufilter_end);

MODULE_AUTHOR("5aboteur <5aboteur@protonmail.com>");
MODULE_DESCRIPTION("Filters incoming & outgoing packets");
MODULE_LICENSE("GPL");
