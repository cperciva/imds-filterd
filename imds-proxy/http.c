#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "sock.h"
#include "warnp.h"

#include "imds-proxy.h"

#define BUFLEN 1024

/**
 * http_proxy(s, dst, id, imdsc):
 * Read an HTTP request from the socket ${s} and forward it to address ${dst},
 * after querying ${id} about the owner of the incoming connection and
 * checking against the ruleset ${imdsc}.
 */
void
http_proxy(int s, struct sock_addr * const * dst,
    struct sock_addr * const * id, const struct imds_conf * imdsc)
{
	char buf[BUFLEN];
	uid_t uid;
	gid_t * gids;
	size_t ngid;
	FILE * client;
	char * request;
	char * path;
	int s_imds;
	FILE * f_imds;
	size_t len;
	int allowed;

	/* Look up the owner of this connect. */
	if (ident(s, id, &uid, &gids, &ngid)) {
		/* Drop the connection. */
		goto done0;
	}

//	warn0("XXX uid = %d", (int)uid);
//	warn0("XXX ngid = %zu", ngid);
//	for (size_t i = 0; i < ngid; i++)
//		warn0("XXX gid[%zu] = %d", i, gids[i]);

	/* Convert the file descriptor into a buffered file. */
	if ((client = fdopen(s, "r+")) == NULL) {
		warnp("fdopen");
		goto done1;
	}

	/* Read and parse the request. */
	if (request_read(client, &request, &path)) {
		warnp("HTTP request read failed");
		goto done2;
	}

//	warn0("XXX HTTP path: ===>%s<===", path);
//	warn0("XXX HTTP request:\n======\n%s\n=====\n", request);

	/* Check whether this process is allowed to make this request. */
	allowed = conf_check(imdsc, path, uid, gids, ngid);

	/* Log request. */
	syslog(LOG_INFO, "imds-proxy: %s uid %zu %s",
	    allowed ? "ALLOW" : "DENY", (size_t)uid, path);

	/* Drop disallowed requests. */
	if (!allowed) {
		fprintf(client, "HTTP/1.0 403 Forbidden\r\n\r\n");
		goto done3;
	}

	/* Open a connection to the IMDS and wrap it into a FILE. */
	if ((s_imds = sock_connect_blocking(dst)) == -1) {
		warnp("sock_connect_blocking");
		goto done3;
	}
	if ((f_imds = fdopen(s_imds, "r+")) == NULL) {
		warnp("fdopen");
		close(s_imds);
		goto done3;
	}

	/* Send the request. */
	if (fwrite(request, strlen(request), 1, f_imds) != 1) {
		warnp("fwrite");
		goto done4;
	}

	/* Forward the server's response back. */
	do {
		if ((len = fread(buf, 1, BUFLEN, f_imds)) == 0)
			break;
		if (fwrite(buf, len, 1, client) != 1)
			break;
	} while (1);

	/* No point checking ferror; we don't handle errors anyway. */

done4:
	fclose(f_imds);
done3:
	free(request);
	free(path);
done2:
	fclose(client);
	s = -1;
done1:
	/* Free the list of gids. */
	free(gids);
done0:
	if (s != -1)
		close(s);
}
