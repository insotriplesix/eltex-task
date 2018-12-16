/********************************************************************
 * PROGRAM: tufilter
 * FILE: tufilter.h
 * PURPOSE: a header file for tufilter.c & user.c
 * AUTHOR: 5aboteur <5aboteur@protonmail.com>
 *******************************************************************/

#ifndef __TUFILTER_H__
#define __TUFILTER_H__

#define DEV_NAME "tufilter"

#define MAX_IP_ADDR_LEN 16
#define MAX_PORT_NUMBER 65536
#define MAX_RULES_NUM 10

typedef struct {
	char ip_addr[MAX_IP_ADDR_LEN];
	uint16_t port;
	uint8_t flags;
} rule_t;

/******************************
  Flags:
    000[1] - proto (TCP/UDP)
    00[1]0 - filter (ON/OFF)
    0[1]00 - route (IN/OUT)
 ******************************/

#define SET_PROTO_TCP(r) (r.flags |= (uint8_t)0x1)
#define SET_PROTO_UDP(r) (r.flags |= (uint8_t)0x0)

#define SET_FILTER_ON(r) (r.flags |= (uint8_t)0x2)
#define SET_FILTER_OFF(r) (r.flags |= (uint8_t)0x0)

#define SET_ROUTE_IN(r) (r.flags |= (uint8_t)0x4)
#define SET_ROUTE_OUT(r) (r.flags |= (uint8_t)0x0)

#define GET_PROTO(r) ((r.flags & (uint8_t)0x1) ? "TCP" : "UDP")
#define GET_FILTER(r) ((r.flags & (uint8_t)0x2) ? 1 : 0)
#define GET_ROUTE(r) ((r.flags & (uint8_t)0x4) ? "IN" : "OUT")

#define MAJOR_NUM 444
#define MINOR_NUM 0
#define MINOR_CNT 1

#define IOCTL_CLR_BUF_POS _IO(MAJOR_NUM, 0)
#define IOCTL_GET_RULES_NUM _IOR(MAJOR_NUM, 1, uint32_t *)
#define IOCTL_GET_RULE _IOR(MAJOR_NUM, 2, rule_t *)
#define IOCTL_SET_RULE _IOW(MAJOR_NUM, 3, rule_t *)

#endif

