/********************************************************************
 * PROGRAM: tufilter
 * FILE: user.c
 * PURPOSE: main user space routines, get blocking rules, show stats
 * AUTHOR: 5aboteur <5aboteur@protonmail.com>
 *******************************************************************/

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "tufilter.h"

/* --------------------------------------------------------------- */

#define C_INF "\033[1;36m"
#define C_ERR "\033[1;31m"
#define C_WRN "\033[1;33m"
#define C_DEF "\033[0m"

#define INF(msg, ...) \
	fprintf(stdout, C_INF"INFO: "C_DEF msg "\n", ##__VA_ARGS__)

#define ERR(msg, ...) \
	fprintf(stderr, C_ERR"ERR: "C_DEF msg "\n", ##__VA_ARGS__); \
	close(dev_fd); \
	exit(EXIT_FAILURE)

#define WRN(msg) \
	fprintf(stdout, C_WRN"WARN: "C_DEF msg "\n")

static const struct option long_options[] = {
	{ "ip", required_argument, 0, 'i' },
	{ "filter", required_argument, 0, 'f' },
	{ "port", required_argument, 0, 'p' },
	{ "route", required_argument, 0, 'r' },
	{ "show", no_argument, 0, 's' },
	{ "transport", required_argument, 0, 't' },
	{ "help", no_argument, 0, '?' },
	{ 0, 0, 0, 0 }
};

// Flag to dump statistics
static int show_stats;

// Flag to dump usage msg
static int show_usage;

// IOCTL funcs
void ioctl_set_rule(rule_t *rule);
void ioctl_get_rules(void);

// Other stuff
void init_rule(rule_t *rule);
void parse_rule(rule_t *rule, int argc, char *argv[]);
void dump_usage_msg(void);
int is_valid_ip(char *ip_addr);

static int dev_fd;

/* --------------------------------------------------------------- */

int main(int argc, char *argv[])
{
	rule_t rule;

	dev_fd = open(DEV_NAME, O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "ERR: open file failed");
		exit(EXIT_FAILURE);
	}

	init_rule(&rule);
	parse_rule(&rule, argc, argv);

	if (rule.port || rule.ip_addr) {
		ioctl_set_rule(&rule);
	}
	else {
		WRN("port or ip not specified");
	}

	if (show_stats) {
		ioctl_get_rules();
	}

	if (show_usage) {
		dump_usage_msg();
	}

	close(dev_fd);

	return 0;
}

void ioctl_set_rule(rule_t *rule)
{
	int rval = ioctl(dev_fd, IOCTL_SET_RULE, rule);
	if (rval < 0) {
		ERR("ioctl set rule failed, rval ~> '%d'", rval);
	}
}

void ioctl_get_rules(void)
{
	struct sockaddr_in sa;
	char ip_addr[INET_ADDRSTRLEN];
	char port[MAX_PORT_STRLEN]; // port in ascii
	unsigned rules_num = 0;
	int rval;
	rule_t rule;

	rval = ioctl(dev_fd, IOCTL_GET_RULES_NUM, &rules_num);
	if (rval < 0) {
		ERR("ioctl get rules num failed, rval ~> '%d'", rval);
	}

	if (rules_num == 0) {
		INF("table is empty (%u)", rules_num);
		return;
	}

	rval = ioctl(dev_fd, IOCTL_TABLE_ZPOS);
	if (rval < 0) {
		ERR("ioctl clr table zpos failed, rval ~> '%d'", rval);
	}

	puts("+------------------------------------------------------------+");
	puts("|  # |    ip address    |  port | proto | route |    drops   |");
	puts("+------------------------------------------------------------+");

	for (unsigned i = 0; i < rules_num; ++i) {
		rval = ioctl(dev_fd, IOCTL_GET_RULE, &rule);
		if (rval < 0) {
			ERR("ioctl get rules failed, rval ~> '%d'", rval);
		}

		// Convert a port number into printable format
		if (rule.port) {
			sprintf(port, "%hu", rule.port);
		}
		else {
			sprintf(port, "N/A");
		}

		sa.sin_addr.s_addr = htonl(rule.ip_addr);

		// Convert an ip addr into printable format
		if (sa.sin_addr.s_addr) {
			inet_ntop(AF_INET, &(sa.sin_addr), ip_addr,
				INET_ADDRSTRLEN);
		}
		else {
			sprintf(ip_addr, "N/A");
		}

		printf("| %2u | %16s | %5s | %5s | %5s | %10u |\n",
			i + 1, ip_addr, port, ((rule.proto == IPPROTO_TCP)
			? "TCP" : "UDP"), ((GET_ROUTE(rule)) ? "IN" : "OUT"),
			rule.drop_cnt);
	}

	puts("+------------------------------------------------------------+");
}

void init_rule(rule_t *rule)
{
	rule->drop_cnt = 0;
	rule->ip_addr = 0;
	rule->port = 0;
	rule->proto = 0;
	rule->flags = 0;
}

void parse_rule(rule_t *rule, int argc, char *argv[])
{
	int arg;
	int option_idx = 0;
	unsigned port;

	struct sockaddr_in sa;

	if (argc == 1) {
		ERR("no arguments passed, argc = %d", argc);
	}

	while (0x1) {
		arg = getopt_long(argc, argv, "i:f:?p:r:st:",
			long_options, &option_idx);

		if (arg < 0) {
			break;
		}

		switch (arg) {
			case 'i':
				if (inet_pton(AF_INET, optarg, &(sa.sin_addr))) {
					rule->ip_addr = ntohl(sa.sin_addr.s_addr);
				}
				else {
					ERR("invalid ip address '%s'", optarg);
				}
				break;
			case 'f':
				if (strcmp(optarg, "enable") == 0) {
					SET_FILTER_ON((*rule));
				}
				else if (strcmp(optarg, "disable") != 0) {
					ERR("incorrect filter option '%s'", optarg);
				}
				break;
			case '?':
				show_usage = 1;
				break;
			case 'p':
				port = atoi(optarg);
				if (port < USHRT_MAX) {
					rule->port = port;
				}
				else {
					ERR("invalid port number (max: %hu, yours: %u)",
						USHRT_MAX, port);
				}
				break;
			case 'r':
				if (strcmp(optarg, "in") == 0) {
					SET_ROUTE_IN((*rule));
				}
				else if (strcmp(optarg, "out") != 0) {
					ERR("incorrect route directon '%s'", optarg);
				}
				break;
			case 's':
				show_stats = 1;
				break;
			case 't':
				if (strcmp(optarg, "tcp") == 0) {
					rule->proto = IPPROTO_TCP;
				}
				else if (strcmp(optarg, "udp") == 0) {
					rule->proto = IPPROTO_UDP;
				}
				else {
					ERR("incorrect proto type '%s'", optarg);
				}
				break;
			default:
				INF("getopt returned %d", arg);
		}
	}
}

void dump_usage_msg(void)
{
	int c;

	puts("Usage: prog [-?s] (-i <ip> | -p <port>) -f <filter>"
		" -r <route> -t <proto>");

	for (int i = 0; long_options[i].name != 0; ++i) {
		c = long_options[i].val;
		printf("  -%c, --%s ", c, long_options[i].name);

		switch (c) {
			case 'i':
				printf("       ");
				puts(": ip address to block (fmt: a.b.c.d)");
				break;
			case 'f':
				printf("   ");
				puts(": filter (enable/disable)");
				break;
			case 'p':
				printf("     ");
				puts(": port number");
				break;
			case 'r':
				printf("    ");
				puts(": route direction (in/out)");
				break;
			case 's':
				printf("     ");
				puts(": print blocked rules");
				break;
			case 't':
				puts(": data transfer protocol (tcp/udp)");
				break;
			case '?':
				printf("     ");
				puts(": display this message");
				break;
		}
	}
}
