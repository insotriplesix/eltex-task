/********************************************************************
 * PROGRAM: tufilter
 * FILE: user.c
 * PURPOSE: main user space routines, get blocking rules, show stats
 * AUTHOR: 5aboteur <5aboteur@protonmail.com>
 *******************************************************************/

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "tufilter.h"

/* --------------------------------------------------------------- */

// Flag to dump statistics
static int show_stats;

// Flag to dump usage msg
static int show_usage;

// IOCTL funcs
void ioctl_set_rule(int fd, rule_t *rule);
void ioctl_get_rules(int fd);

// Other stuff
void init_rule(rule_t *rule);
void parse_rule(rule_t *rule, int argc, char *argv[]);

void dump_usage_msg(void);
void dump_err(char *msg);

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

	if (rule.port || (strcmp(rule.ip_addr, "N/A") != 0)) {
		ioctl_set_rule(dev_fd, &rule);
	}
	else {
		fprintf(stderr, "WARN: port or ip not specified\n");
	}

	if (show_stats) {
		ioctl_get_rules(dev_fd);
	}

	if (show_usage) {
		dump_usage_msg();
	}

	close(dev_fd);

	return 0;
}

void ioctl_set_rule(int fd, rule_t *rule)
{
	int rval;
	uint32_t rules_num = MAX_RULES_NUM;

	rval = ioctl(fd, IOCTL_GET_RULES_NUM, &rules_num);
	if (rval < 0) {
		dump_err("ioctl get rules num failed");
	}

	if ((rules_num >= MAX_RULES_NUM) &&
		(GET_FILTER((*rule)))) {
		fprintf(stdout, "INF: table is full\n");
		return;
	}

	rval = ioctl(fd, IOCTL_CLR_BUF_POS);
	if (rval < 0) {
		dump_err("ioctl clr buf pos failed");
	}

	rval = ioctl(fd, IOCTL_SET_RULE, rule);
	if (rval < 0) {
		dump_err("ioctl set rule failed");
	}
}

void ioctl_get_rules(int fd)
{
	char port[8]; // port in ascii
	int rval;
	uint32_t rules_num = 0;
	rule_t rule;

	rval = ioctl(fd, IOCTL_GET_RULES_NUM, &rules_num);
	if (rval < 0) {
		dump_err("ioctl get rules num failed");
	}

	if (rules_num == 0) {
		fprintf(stdout, "INF: table is empty\n");
		return;
	}

	rval = ioctl(fd, IOCTL_CLR_BUF_POS);
	if (rval < 0) {
		dump_err("ioctl clr buf pos failed");
	}

	puts("+-----------------------------------------------+");
	puts("|  # |    ip address    |  port | proto | route |");
	puts("+-----------------------------------------------+");

	for (uint32_t i = 0; i < rules_num; ++i) {
		rval = ioctl(fd, IOCTL_GET_RULE, &rule);
		if (rval < 0) {
			dump_err("ioctl get rules failed");
		}

		// Convert port number into ascii format
		if (rule.port) {
			sprintf(port, "%d", ntohs(rule.port));
		}
		else {
			sprintf(port, "N/A");
		}

		printf("| %2d | %16s | %5s | %5s | %5s |\n", i + 1,
			rule.ip_addr, port, GET_PROTO(rule), GET_ROUTE(rule));
	}

	puts("+-----------------------------------------------+");
}

void init_rule(rule_t *rule)
{
	strcpy(rule->ip_addr, "N/A");
	rule->port = 0;
	rule->flags = 0;
}

void parse_rule(rule_t *rule, int argc, char *argv[])
{
	if (argc == 1) {
		dump_err("no arguments passed");
	}

	for (int i = 1; i < argc; ++i) {
		if ((strcmp(argv[i], "-i") == 0) ||
			(strcmp(argv[i], "--ip") == 0)) {
				if (++i < argc) {
					if (strlen(argv[i]) < MAX_IP_ADDR_LEN) {
						sprintf(rule->ip_addr, "%s", argv[i]);
					}
					else {
						dump_err("invalid ip address");
					}
				}
		}
		else if ((strcmp(argv[i], "-f") == 0) ||
			(strcmp(argv[i], "--filter") == 0)) {
				if (++i < argc) {
					if (strcmp(argv[i], "enable") == 0) {
						SET_FILTER_ON((*rule));
					}
					else if (strcmp(argv[i], "disable") == 0) {
						SET_FILTER_OFF((*rule));
					}
					else {
						dump_err("incorrect filter option");
					}
				}
		}
		else if ((strcmp(argv[i], "-?") == 0) ||
			(strcmp(argv[i], "--help") == 0)) {
				show_usage = 1;
		}
		else if ((strcmp(argv[i], "-p") == 0) ||
			(strcmp(argv[i], "--port") == 0)) {
				if (++i < argc) {
					unsigned p = atoi(argv[i]);
					if (p < MAX_PORT_NUMBER) {
						rule->port = htons(p);
					}
					else {
						dump_err("incorrect port number");
					}
				}
		}
		else if ((strcmp(argv[i], "-r") == 0) ||
			(strcmp(argv[i], "--route") == 0)) {
				if (++i < argc) {
					if (strcmp(argv[i], "in") == 0) {
						SET_ROUTE_IN((*rule));
					}
					else if (strcmp(argv[i], "out") == 0) {
						SET_ROUTE_OUT((*rule));
					}
					else {
						dump_err("incorrect route directon");
					}
				}
		}
		else if ((strcmp(argv[i], "-s") == 0) ||
			(strcmp(argv[i], "--show") == 0)) {
				show_stats = 1;
		}
		else if ((strcmp(argv[i], "-t") == 0) ||
			(strcmp(argv[i], "--transport") == 0)) {
				if (++i < argc) {
					if (strcmp(argv[i], "tcp") == 0) {
						SET_PROTO_TCP((*rule));
					}
					else if (strcmp(argv[i], "udp") == 0) {
						SET_PROTO_UDP((*rule));
					}
					else {
						dump_err("incorrect proto type");
					}
				}
		}
		else {
			dump_err("incorrect rule");
		}
	}
}


void dump_usage_msg(void)
{
	puts("Usage: prog [-?s] (-i <ip> | -p <port>) -f <filter>"
		" -r <route> -t <proto>");

	puts("  -i (--ip)        : ip address to block (eg: 66.69.9.9)");
	puts("  -f (--filter)    : filter (enable/disable)");
	puts("  -p (--port)      : port number");
	puts("  -r (--route)     : route direction (in/out)");
	puts("  -s (--show)      : prints blocked rules");
	puts("  -t (--transport) : data transfer protocol (tcp/udp)");
	puts("  -? (--help)      : display this message");
}

void dump_err(char *msg)
{
	fprintf(stderr, "ERR: %s\n", msg);
	close(dev_fd);
	exit(EXIT_FAILURE);
}
