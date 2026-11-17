/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wafio_compat.h — UAPI constants not exported via kernel BTF (vmlinux.h).
 *
 * vmlinux.h contains all kernel struct/enum *types* but does not include
 * preprocessor constants from UAPI headers.  Define the small set we need here.
 */

#ifndef __WAFIO_COMPAT_H__
#define __WAFIO_COMPAT_H__

/* Ethernet protocol types (linux/if_ether.h) */
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

/* TC action return codes (linux/pkt_cls.h) */
#define TC_ACT_UNSPEC    (-1)
#define TC_ACT_OK         0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT       2
#define TC_ACT_PIPE       3

/* Socket address families (linux/socket.h) */
#define AF_INET    2
#define AF_INET6   10
#define AF_UNIX    1
#define AF_NETLINK 16
#define AF_RXRPC   33  /* RxRPC socket — used by Dirty Frag LPE exploit (CVE-2026-43284) */

/* IP protocols (linux/in.h) */
#define IPPROTO_ESP 50 /* Encapsulating Security Payload — used by xfrm/Dirty Frag exploit */

/* Socket types (linux/net.h) */
#define SOCK_RAW  3

#endif /* __WAFIO_COMPAT_H__ */
