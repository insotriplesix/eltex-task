/********************************************************************
 * PROGRAM: tufilter
 * FILE: tufilter.h
 * PURPOSE: a header file for tufilter.c & user.c
 * AUTHOR: 5aboteur <5aboteur@protonmail.com>
 *******************************************************************/

#ifndef __TUFILTER_H__
#define __TUFILTER_H__

#define DEV_NAME "tufilter"

/* MAX: '65535\0' */
#define MAX_PORT_STRLEN 6

/* MAX: 'rule #10: 4294967295 packets dropped\0\n' */
#define MAX_RULE_STRLEN 38

#define MAX_RULES_NUM 10

typedef struct {
	uint32_t drop_cnt;
	uint32_t ip_addr;
	uint16_t port;
	uint8_t proto;
	uint8_t flags;
} rule_t;

/**********************************
  Flags:
   ..000[1] - filter, 1-ON,  0-OFF
   ..00[1]0 - route,  1-IN,  0-OUT
 **********************************/

#define FILTER_ON (uint8_t)(0x1)
#define ROUTE_IN (uint8_t)(0x2)
#define ROUTE_OUT (uint8_t)(0x0)

#define SET_FILTER_ON(r) (r.flags |= FILTER_ON)
#define SET_ROUTE_IN(r) (r.flags |= ROUTE_IN)

#define GET_FILTER(r) (r.flags & FILTER_ON)
#define GET_ROUTE(r) (r.flags & ROUTE_IN)

#define MAJOR_NUM 444
#define MINOR_NUM 0
#define MINOR_CNT 1

#define IOCTL_TABLE_ZPOS _IO(MAJOR_NUM, 0)
#define IOCTL_GET_RULES_NUM _IOR(MAJOR_NUM, 1, uint32_t *)
#define IOCTL_GET_RULE _IOR(MAJOR_NUM, 2, rule_t *)
#define IOCTL_SET_RULE _IOW(MAJOR_NUM, 3, rule_t *)

#endif

