#define __BSD_VISIBLE	1	/* Needed for net/ headers. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "warnp.h"

#include "imds-filterd.h"

static int
sysctldump(int mib[], size_t miblen, char ** buf, size_t * len)
{

	/* Loop until we manage to dump the table. */
	while (1) {
		/* How large a buffer do we need? */
		if (sysctl(mib, miblen, NULL, len, NULL, 0)) {
			warnp("sysctl");
			goto err0;
		}

		/* Allocate a buffer based on the size the kernel reported. */
		if ((*buf = malloc(*len)) == NULL) {
			warnp("malloc");
			goto err0;
		}

		/* Try to dump the table. */
		if (sysctl(mib, miblen, *buf, len, NULL, 0)) {
			if (errno == ENOMEM) {
				/*
				 * The table we're dumping must have grown;
				 * free our buffer and start over.
				 */
				free(*buf);
				continue;
			}
			warnp("sysctl");
			goto err1;
		}

		/* It worked this time. */
		break;
	}

	/* Success! */
	return (0);

err1:
	free(*buf);
err0:
	/* Failure! */
	return (-1);
}

static int
extractaddrs(char * p, struct sockaddr * sas[RTAX_MAX])
{
	struct rt_msghdr * rt = (struct rt_msghdr *)p;
	struct sockaddr * sa;
	char * p2;
	int i;

	/* No addresses yet. */
	for (i = 0; i < RTAX_MAX; i++)
		sas[i] = NULL;

	/* Move through the buffer recording pointers to addresses. */
	for (i = 0, p2 = &p[sizeof(struct rt_msghdr)];
	    p2 < &p[rt->rtm_msglen];
	    p2 += SA_SIZE(sa)) {
		sa = (struct sockaddr *)p2;
		if (p2 + SA_SIZE(sa) > &p[rt->rtm_msglen]) {
			warn0("Socket address overflows routing message!");
			goto err0;
		}

		/* Which address type is this? */
		if ((i = ffs(rt->rtm_addrs & ~((1 << i) - 1))) == 0) {
			warn0("Routing message contains wrong number of addresses!");
			goto err0;
		}
		sas[i - 1] = sa;
	}
	if ((rt->rtm_addrs & ~((1 << i) - 1)) != 0) {
		warn0("Routing message contains wrong number of addresses!");
		goto err0;
	}

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

/**
 * netconfig_getif(srcaddr, gwaddr, host, ifname):
 * Find the IPv4 route used for sending packets to ${host}; return via
 * ${ifname}, ${gwaddr}, and ${srcaddr} the name of the network interface,
 * the gateway, and the appropriate source IPv4 address.
 */
int
netconfig_getif(struct sockaddr_in * srcaddr, struct sockaddr_in * gwaddr,
    in_addr_t imdsaddr, char ** ifname)
{
	struct sockaddr * sas[RTAX_MAX];
	int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
	in_addr_t rtdst, rtmsk;
	int64_t best_rtmsk = -1;
	u_short best_index = (u_short)-1;
	struct sockaddr * best_addr = NULL;
	struct sockaddr * best_gwaddr = NULL;
	char * buf;
	char * p;
	struct rt_msghdr * rt;
	size_t len;

	/* Dump the routing table. */
	if (sysctldump(mib, sizeof(mib) / sizeof(mib[0]), &buf, &len))
		goto err0;

	/*
	 * Walk through the routing table we just dumped, looking for the
	 * best route to the Instance Metadata Service.
	 */
	for (p = buf; p < &buf[len]; p += rt->rtm_msglen) {
		/* We have a routing message. */
		rt = (struct rt_msghdr *)p;
		if ((&p[sizeof(struct rt_msghdr)] > &buf[len]) ||
		    (&p[rt->rtm_msglen] > &buf[len])) {
			warn0("Routing message overflows sysctl buffer!");
			goto err1;
		}

		/* It should be an RTM_GET message. */
		if (rt->rtm_type != RTM_GET) {
			warn0("Unexpected routing message type: %d",
			    (int)rt->rtm_type);
			continue;
		}

		/* Extract addresses from the message. */
		if (extractaddrs(p, sas))
			goto err1;

		/* We only care about IPv4 destinations. */
		if ((sas[RTAX_DST] == NULL) ||
		    (sas[RTAX_DST]->sa_family != AF_INET))
			continue;
		rtdst = ((struct sockaddr_in *)(sas[RTAX_DST]))->sin_addr.s_addr;

		/* Ignore any route which doesn't match the netmask. */
		if (sas[RTAX_NETMASK] != NULL) {
			/* Sanity-check. */
			if (sas[RTAX_NETMASK]->sa_family != AF_INET) {
				warn0("Interface has IPv4 address"
				    " but non-IPv4 netmask!");
				continue;
			}
			rtmsk = ((struct sockaddr_in *)(sas[RTAX_NETMASK]))->sin_addr.s_addr;
		} else {
			rtmsk = (in_addr_t)0xffffffff;
		}
		if (((imdsaddr ^ rtdst) & rtmsk) != 0)
			continue;

		/* Pick the most specific route. */
		if (ntohl(rtmsk) >= best_rtmsk) {
			best_rtmsk = ntohl(rtmsk);
			best_index = rt->rtm_index;
			best_gwaddr = sas[RTAX_GATEWAY];
			best_addr = sas[RTAX_IFA];
		}
	}

	/* Did we find a route? */
	if (best_rtmsk == -1) {
		warn0("No route to Instance Metadata Service found!");
		goto err1;
	}

	/* Does that interface have a local address? */
	if (best_addr == NULL) {
		warn0("Best route has no local address!");
		goto err1;
	}
	if (best_addr->sa_family != AF_INET) {
		warn0("IPv4 route has non-IPv4 interface address!");
		goto err1;
	}

	/* Is there a gateway? */
	if (best_gwaddr == NULL) {
		warn0("Best route has no gateway address!");
		goto err1;
	}
	if (best_gwaddr->sa_family != AF_INET) {
		warn0("IPv4 route has non-IPv4 gateway address!");
		goto err1;
	}

	/* Allocate space for the interface name. */
	if ((*ifname = malloc(IFNAMSIZ)) == NULL)
		goto err1;

	/* Return the local address and interface name. */
	memcpy(srcaddr, best_addr, best_addr->sa_len);
	memcpy(gwaddr, best_gwaddr, best_gwaddr->sa_len);
	if_indextoname(best_index, *ifname);

	/* Success! */
	return (0);

err1:
	free(buf);
err0:
	/* Failure! */
	return (-1);
}

/*
 * netconfig_getmac(host, mac):
 * Look up the MAC address associated with the IPv4 address ${host} and
 * return it via ${mac}.  Note that this can fail if ${host} is not in the
 * operating system's ARP cache.
 */
int
netconfig_getmac(struct sockaddr_in * host, uint8_t mac[6])
{
	struct sockaddr * sas[RTAX_MAX];
	int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
	char * buf;
	char * p;
	struct rt_msghdr * rt;
	size_t len;

	/* Dump the ARP table. */
	if (sysctldump(mib, sizeof(mib) / sizeof(mib[0]), &buf, &len))
		goto err0;

	/*
	 * Walk through the ARP table we just dumped, looking for the entry
	 * corresponding to the IPv4 address we have.
	 */
	for (p = buf; p < &buf[len]; p += rt->rtm_msglen) {
		/* We have a routing message. */
		rt = (struct rt_msghdr *)p;
		if ((&p[sizeof(struct rt_msghdr)] > &buf[len]) ||
		    (&p[rt->rtm_msglen] > &buf[len])) {
			warn0("Routing message overflows sysctl buffer!");
			goto err1;
		}

		/* It should be an RTM_GET message. */
		if (rt->rtm_type != RTM_GET) {
			warn0("Unexpected routing message type: %d",
			    (int)rt->rtm_type);
			continue;
		}

		/* Extract addresses from the message. */
		if (extractaddrs(p, sas))
			goto err1;

		/* Is this the one we're looking for? */
		if (sas[RTAX_DST] == NULL)
			continue;
		if (sas[RTAX_DST]->sa_family != AF_INET)
			continue;
		if (((struct sockaddr_in *)(sas[RTAX_DST]))->sin_addr.s_addr
		    != host->sin_addr.s_addr)
			continue;

		/* Do we have a link-layer address? */
		if (sas[RTAX_GATEWAY] == NULL)
			continue;
		if (sas[RTAX_GATEWAY]->sa_family != AF_LINK)
			continue;

		/* Copy the address out. */
		memcpy(mac, LLADDR((struct sockaddr_dl *)sas[RTAX_GATEWAY]), 6);
		break;
	}

	/* Success! */
	return (0);

err1:
	free(buf);
err0:
	/* Failure! */
	return (-1);
}
