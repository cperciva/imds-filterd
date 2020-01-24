#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <stdlib.h>

#include "elasticarray.h"
#include "events.h"
#include "network.h"
#include "sock.h"
#include "warnp.h"

#include "imds-filterd.h"

/* Buffer up to 4kB at once. */
#define BUFLEN 4096

/*
 * List of sockets we have connecting to the target.  We maintain this list
 * so that we can perform "is this TCP/IP packet part of a connection we own"
 * queries (via conns_isours) in order to decide whether to redirect packets
 * into the IMDS proxy jail or allow them out the external interface.
 */
ELASTICARRAY_DECL(SOCKETLIST, socketlist, int);
static SOCKETLIST sl;

/* Add socket to the elastic array of connections. */
static int
sockadd(int s)
{

	return (socketlist_append(sl, &s, 1));
}

/* Remove socket from the elastic array of connections. */
static void
sockremove(int s)
{
	size_t size = socketlist_getsize(sl);
	size_t i;

	/* Find the socket in the array. */
	for (i = 0; i < size; i++) {
		if (*socketlist_get(sl, i) == s)
			break;
	}

	/* We should have found it. */
	assert(i < size);

	/* Move the last socket in the array into this position and shrink. */
	*socketlist_get(sl, i) = *socketlist_get(sl, size - 1);
	socketlist_shrink(sl, 1);
}

/* State for one direction of one connection. */
struct ustate {
	int si;
	int so;
	struct cstate * cs;
	void * read_cookie;
	void * write_cookie;
	uint8_t buf[BUFLEN];
};

/* State for one connection. */
struct cstate {
	int sl;
	int sr;
	struct ustate * d[2];
};

/* State for connection accepting. */
struct astate {
	int s;
	struct sock_addr * tgt;
};

/* Forward declarations. */
static int callback_read(void *, ssize_t);
static int callback_write(void *, ssize_t);
static void dropconn(struct cstate *);

/* Push bits from src to dst. */
static struct ustate *
pushbits(int src, int dst, struct cstate * cs)
{
	struct ustate * d;

	/* Allocate a state structure. */
	if ((d = malloc(sizeof(struct ustate))) == NULL)
		goto err0;

	/* Set initial state. */
	d->si = src;
	d->so = dst;
	d->cs = cs;
	d->write_cookie = NULL;

	/* Start reading. */
	if ((d->read_cookie = network_read(d->si, d->buf, BUFLEN, 1,
	    callback_read, d)) == NULL)
		goto err1;

	/* Success! */
	return (d);

err1:
	free(d);
err0:
	/* Failure! */
	return (NULL);
}

/* Callback for reading bits. */
static int
callback_read(void * cookie, ssize_t len)
{
	struct ustate * d = cookie;

	/* This callback is no longer pending. */
	d->read_cookie = NULL;

	/* Error?  EOF? */
	switch (len) {
	case 0:
		/* Close the write side (aka send a FIN). */
		shutdown(d->so, SHUT_WR);

		/* If both sides are closed, clean up. */
		if ((d->cs->d[0]->read_cookie != NULL) ||
		    (d->cs->d[0]->write_cookie != NULL) ||
		    (d->cs->d[1]->read_cookie != NULL) ||
		    (d->cs->d[1]->write_cookie != NULL))
			break;
		/* FALLTHROUGH */
	case -1:
		/* Drop the connection. */
		dropconn(d->cs);
		break;
	default:
		/* Write out the data we read. */
		if ((d->write_cookie = network_write(d->so, d->buf,
		    (size_t)len, (size_t)len, callback_write, d)) == NULL)
			goto err0;
	}

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

/* Callback for writing bits. */
static int
callback_write(void * cookie, ssize_t len)
{
	struct ustate * d = cookie;

	/* This callback is no longer pending. */
	d->write_cookie = NULL;

	/* Error? */
	if (len == -1)
		dropconn(d->cs);

	/* Read more data. */
	if ((d->read_cookie = network_read(d->si, d->buf, BUFLEN, 1,
	    callback_read, d)) == NULL)
		goto err0;

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

/* Cancel and free a pushbits. */
static void
pushbits_cancel(struct ustate * d)
{

	/* Cancel network operations, if any. */
	if (d->read_cookie)
		network_read_cancel(d->read_cookie);
	if (d->write_cookie)
		network_write_cancel(d->write_cookie);

	/* Free the state structure. */
	free(d);
}

/* Drop a connection. */
static void
dropconn(struct cstate * cs)
{

	/* Cancel both directions. */
	pushbits_cancel(cs->d[0]);
	pushbits_cancel(cs->d[1]);

	/* Remove socket from our list of connections passing packets. */
	sockremove(cs->sr);

	/* Close sockets. */
	close(cs->sl);
	close(cs->sr);

	/* Free the state structure. */
	free(cs);
}

/* We connected to the target. */
static int
callback_connect(void * cookie)
{
	struct cstate * cs = cookie;

	/* Start pushing bits from client to server. */
	if ((cs->d[0] = pushbits(cs->sl, cs->sr, cs)) == NULL)
		goto err0;

	/* Start pushing bits from server to client. */
	if ((cs->d[1] = pushbits(cs->sr, cs->sl, cs)) == NULL)
		goto err1;

	return (0);

err1:
	pushbits_cancel(cs->d[0]);
err0:
	/* Failure! */
	return (-1);
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
	cs->sl = s;

	/*
	 * Attempt to connect to the target host.  The outgoing SYN will go
	 * through our tunnel; but since we're running in a single thread,
	 * we'll record the descriptor here before we read the SYN out of the
	 * tunnel, so we'll let it through.
	 */
	if ((cs->sr = sock_connect_nb(as->tgt)) == -1) {
		warnp("sock_connect_nb");
		goto err2;
	}

	/* Add this socket to our list of outgoing connections. */
	if (sockadd(cs->sr))
		goto err3;

	/* The socket becomes writable upon connecting (or failing to). */
	if (events_network_register(callback_connect, cs, cs->sr,
	    EVENTS_NETWORK_OP_WRITE))
		goto err4;

	/* Accept more connections. */
	if (network_accept(as->s, gotconn, as) == NULL) {
		warnp("network_accept");
		goto err0;
	}

	/* Success! */
	return (0);

err4:
	sockremove(cs->sr);
err3:
	close(cs->sr);
err2:
	free(cs);
err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * conns_setup(path, dstaddr):
 * Create a socket at ${path}.  Forward data between incoming connections and
 * TCP connection to ${dstaddr}.
 */
int
conns_setup(const char * path, const char * dstaddr)
{
	struct sock_addr ** sas_s;
	struct sock_addr ** sas_t;
	struct astate * as;

	/* Initialize socket list. */
	if (sl == NULL) {
		if ((sl = socketlist_init(0)) == NULL)
			goto err0;
	}

	/* Allocate a state structure. */
	if ((as = malloc(sizeof(struct astate))) == NULL)
		goto err0;

	/* Resolve the listening path and target address. */
	if ((sas_s = sock_resolve(path)) == NULL) {
		warnp("sock_resolve");
		goto err1;
	}
	if ((sas_t = sock_resolve(dstaddr)) == NULL) {
		warnp("sock_resolve");
		goto err2;
	}

	/* Listen for incoming connections. */
	if ((as->s = sock_listener(sas_s[0])) == -1) {
		warnp("sock_listener");
		goto err3;
	}
	if (network_accept(as->s, gotconn, as) == NULL) {
		warnp("network_accept");
		goto err4;
	}

	/*
	 * Record the first target address; we'll connect to it later.  Free
	 * the list; we don't need it.
	 */
	as->tgt = sas_t[0];
	free(sas_t);

	/* Free the source addresses; we don't need them any more. */
	sock_addr_freelist(sas_s);

	/* Success! */
	return (0);

err4:
	close(as->s);
err3:
	sock_addr_freelist(sas_t);
err2:
	sock_addr_freelist(sas_s);
err1:
	free(as);
err0:
	/* Failure! */
	return (-1);
}

/**
 * conns_isours(srcaddr, srcport):
 * Return nonzero if one of our connections to the target has source address
 * srcaddr:srcport.
 */
int
conns_isours(in_addr_t srcaddr, uint16_t srcport)
{
	size_t i;
	int s;
	struct sockaddr_in sin;
	socklen_t sinlen;

	/* Iterate through sockets checking if they match. */
	for (i = 0; i < socketlist_getsize(sl); i++) {
		s = *socketlist_get(sl, i);

		/* Does the source address match? */
		sinlen = sizeof(sin);
		if (getsockname(s, (struct sockaddr *)&sin, &sinlen)) {
			/*
			 * Not fatal; we can get this if a RST arrives
			 * at an inconvenient moment, for example.
			 */
			continue;
		}
		if ((sin.sin_family != AF_INET) ||
		    (ntohl(sin.sin_addr.s_addr) != srcaddr) ||
		    (ntohs(sin.sin_port) != srcport))
			continue;

		/* Found it! */
		return (1);
	}

	/* No matching connection found. */
	return (0);
}
