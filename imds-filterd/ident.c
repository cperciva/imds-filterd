#define __BSD_VISIBLE	1	/* Needed for sys/ucred.h header. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>

#include <netinet/in.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network.h"
#include "sock.h"
#include "warnp.h"

#include "imds-filterd.h"

/* State for connection accepting. */
struct astate {
	int s;
};

/* State for a single connection. */
struct cstate {
	int s;
	uint8_t inbuf[12];
	char outbuf[sizeof(uid_t) * 3 + 1 + XU_NGROUPS * (sizeof(gid_t) * 3 + 1) + 1];
	size_t olen;
};

/* We have sent a response. */
static int
sentdata(void * cookie, ssize_t len)
{
	struct cstate * cs = cookie;

	/* Don't care if we succeeded. */
	(void)len; /* UNUSED */

	/* Clean up the connection. */
	close(cs->s);
	free(cs);

	/* Success! */
	return (0);
}

/* We have data from the client. */
static int
gotdata(void * cookie, ssize_t len)
{
	struct cstate * cs = cookie;
	struct sockaddr_in addrs[2];
	struct xucred uc;
	int printlen;
	size_t size = sizeof(struct xucred);
	size_t i;

	/* Did the read succeed? */
	if ((len == -1) || (len == 0))
		goto drop;

	/* Parse the query. */
	addrs[0].sin_len = sizeof(struct sockaddr_in);
	addrs[0].sin_family = AF_INET;
	memcpy(&addrs[0].sin_addr, &cs->inbuf[0], 4);
	memcpy(&addrs[0].sin_port, &cs->inbuf[4], 2);
	addrs[1].sin_len = sizeof(struct sockaddr_in);
	addrs[1].sin_family = AF_INET;
	memcpy(&addrs[1].sin_addr, &cs->inbuf[6], 4);
	memcpy(&addrs[1].sin_port, &cs->inbuf[10], 2);

	/* Ask the kernel who owns this TCP connection. */
	if (sysctlbyname("net.inet.tcp.getcred", &uc, &size,
	    addrs, sizeof(addrs))) {
		/* Not fatal; we might have lost a race against a close. */
		warnp("sysctlbyname");
		goto drop;
	}

	/* Sanity-check. */
	assert(uc.cr_ngroups <= XU_NGROUPS);

	/* Construct and send a response. */
	if ((printlen = sprintf(cs->outbuf, "%u\n",
	    (unsigned int)uc.cr_uid)) < 0) {
		warnp("sprintf");
		goto drop;
	}
	cs->olen = (size_t)printlen;
	for (i = 0; i < (size_t)uc.cr_ngroups; i++) {
		if ((printlen = sprintf(&cs->outbuf[cs->olen], "%u,",
		    (unsigned int)uc.cr_groups[i])) < 0) {
			warnp("sprintf");
			goto drop;
		}
		cs->olen += (size_t)printlen;
	}
	cs->outbuf[cs->olen - 1] = '\n';
	if (network_write(cs->s, (uint8_t *)cs->outbuf, cs->olen, cs->olen,
	    sentdata, cs) == NULL) {
		warnp("network_write");
		goto drop;
	}

	/* Success! */
	return (0);

drop:
	close(cs->s);
	free(cs);
	return (0);
}

/* A connection has arrived. */
static int
gotconn(void * cookie, int s)
{
	struct astate * as = cookie;
	struct cstate * cs;

	/* If we got a -1 descriptor, something went seriously wrong. */
	if (s == -1) {
		warnp("network_accept");
		goto err0;
	}

	/* Allocate a state structure. */
	if ((cs = malloc(sizeof(struct cstate))) == NULL)
		goto err1;

	/* Record the incoming connection. */
	cs->s = s;

	/* Read the TCP source and destination IP addresses and ports. */
	if (network_read(cs->s, cs->inbuf, 12, 12, gotdata, cs) == NULL) {
		warnp("network_read");
		goto err2;
	}

	/* Accept more connections. */
	if (network_accept(as->s, gotconn, as) == NULL) {
		warnp("network_accept");
		goto err0;
	}

	/* Success! */
	return (0);

err2:
	free(cs);
err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * ident_setup(path):
 * Create a socke at ${path}.  Receive connections and read 12 bytes
 * [4 byte src IP][2 byte src port][4 byte dst IP][2 byte dst port]
 * (in network byte order) then write back "uid\ngid[,gid]*\n".
 */
int
ident_setup(const char * path)
{
	struct sock_addr ** sas_s;
	struct astate * as;

	/* Allocate a state structure. */
	if ((as = malloc(sizeof(struct astate))) == NULL)
		goto err0;

	/* Resolve the listening path and target address. */
	if ((sas_s = sock_resolve(path)) == NULL) {
		warnp("sock_resolve");
		goto err1;
	}

	/* Listen for incoming connections. */
	if ((as->s = sock_listener(sas_s[0])) == -1) {
		warnp("sock_listener");
		goto err2;
	}
	if (network_accept(as->s, gotconn, as) == NULL) {
		warnp("network_accept");
		goto err3;
	}

	/* Free the source addresses; we don't need them any more. */
	sock_addr_freelist(sas_s);

	/* Success! */
	return (0);

err3:
	close(as->s);
err2:
	sock_addr_freelist(sas_s);
err1:
	free(as);
err0:
	/* Failure! */
	return (-1);
}
