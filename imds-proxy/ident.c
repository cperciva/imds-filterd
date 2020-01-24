#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <string.h>

#include "elasticarray.h"
#include "sock.h"
#include "warnp.h"

#include "imds-proxy.h"

/* Elastic array of gids. */
ELASTICARRAY_DECL(GIDLIST, gidlist, gid_t);

/**
 * ident(s, id, uid, gids, ngid):
 * Query ${id} about the ownership of the process holding the other end of
 * the socket ${s}; return the user ID via ${uid}, a malloced array of group
 * IDs via ${gids}, and the number of group IDs via ${ngid}.
 */
int
ident(int s, struct sock_addr * const * id,
    uid_t * uid, gid_t ** gids, size_t * ngid)
{
	struct sockaddr_in al;
	struct sockaddr_in ar;
	socklen_t alen;
	uint8_t idreq[12];
	FILE * f_id;
	int s_id;
	intmax_t i;
	GIDLIST gs;
	gid_t g;

	/* Look up the local and remote addresses of this connection. */
	alen = sizeof(struct sockaddr_in);
	if (getsockname(s, (struct sockaddr *)&al, &alen)) {
		warnp("getsockname");
		goto err0;
	}
	alen = sizeof(struct sockaddr_in);
	if (getpeername(s, (struct sockaddr *)&ar, &alen)) {
		warnp("getpeername");
		goto err0;
	}

	/* Make sure that we got AF_INET addresses. */
	if ((al.sin_family != AF_INET) || (ar.sin_family != AF_INET)) {
		warn0("HTTP connection is not IPv4!");
		goto err0;
	}

	/*
	 * Construct the ident query.  Note that we send the *remote* address
	 * and port first because what we see as remote is seen by the filter
	 * daemon as local and vice versa.
	 */
	memcpy(&idreq[0], &ar.sin_addr, 4);
	memcpy(&idreq[4], &ar.sin_port, 2);
	memcpy(&idreq[6], &al.sin_addr, 4);
	memcpy(&idreq[10], &al.sin_port, 2);

	/* Connect to the ident service and wrap into a FILE. */
	if ((s_id = sock_connect_blocking(id)) == -1) {
		warnp("sock_connect_blocking");
		goto err0;
	}
	if ((f_id = fdopen(s_id, "r+")) == NULL) {
		warnp("fdopen");
		close(s_id);
		goto err0;
	}

	/* Write the query. */
	if (fwrite(idreq, 12, 1, f_id) != 1) {
		warnp("fwrite");
		goto err1;
	}

	/*
	 * Read the user ID into an intmax_t; we don't know how large a uid_t
	 * is so we can't ask fscanf to parse directly into there.
	 */
	if (fscanf(f_id, "%jd\n", &i) != 1) {
		warn0("Could not parse uid from ident daemon!");
		goto err1;
	}
	*uid = i;

	/* Allocate an elastic array of gids. */
	if ((gs = gidlist_init(0)) == NULL)
		goto err1;

	/* Read the group IDs. */
	while (fscanf(f_id, "%jd,", &i) == 1) {
		g = i;
		if (gidlist_append(gs, &g, 1))
			goto err2;
	}

	/* We should have read at least one gid. */
	if (gidlist_getsize(gs) == 0) {
		warn0("Did not read any gids from ident daemon!");
		goto err2;
	}

	/* Export the array. */
	gidlist_export(gs, gids, ngid);

	/* Close the connection to the ident service. */
	fclose(f_id);

	/* Success! */
	return (0);

err2:
	gidlist_free(gs);
err1:
	fclose(f_id);
err0:
	/* Failure! */
	return (-1);
}
