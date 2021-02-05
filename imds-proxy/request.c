#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "asprintf.h"
#include "hexify.h"
#include "warnp.h"

#include "imds-proxy.h"

/**
 * We have two goals here:
 * 1. Valid HTTP requests get the right response.
 * 2. Requests, even if not valid HTTP, cannot bypass the filtering.
 * In particular we need to worry about things like "request smuggling"
 * attacks where an invalid request is parsed differently by a filter vs
 * the end host; and we need to normalize requests so that filtering works
 * (e.g., to make sure that "/safe/path/../../dangerous/stuff" doesn't match
 * "/safe/path/").
 *
 * We currently handle this by
 * (a) parsing the request,
 * (b) normalizing it, and
 * (c) constructing a *new* request from what we parsed,
 * in order to guaranteed that an invalid request can't do anything which a
 * valid request couldn't do.
 *
 * It would be ideal if we could the exact same request-parsing code which
 * the EC2 Instance Metadata Service uses, in order to guarantee bug-for-bug
 * compatibility; but of course that code is not publicly available.
 */

/* Percent-encode a request path. */
static char *
urlencode(char * path)
{
	size_t len;
	char * ep;
	char * p;
	char c;

	/* Compute an upper bound on the allocation length needed. */
	len = strlen(path);
	if (len > (SIZE_MAX - 1) / 3) {
		errno = ENOMEM;
		goto err0;
	}
	len = 3 * len + 1;

	/* Allocate a buffer. */
	if ((ep = malloc(len)) == NULL)
		goto err0;

	/* Fill it, one byte at a time. */
	for (p = ep; *path; path++) {
		c = *path;
		if ((('a' <= c) && (c <= 'z')) ||
		    (('A' <= c) && (c <= 'Z')) ||
		    (('0' <= c) && (c <= '9')) ||
		    (c == '$') || (c == '-') || (c == '_') ||
		    (c == '.') || (c == '+') || (c == '/')) {
			*p++ = c;
		} else {
			*p++ = '%';
			hexify((uint8_t *)&c, p, 1);
			p += 2;
		}
	}

	/* NUL-terminate. */
	*p = '\0';

	/* Return the encoded string. */
	return (ep);

err0:
	/* Failure! */
	return (NULL);
}

/**
 * request_read(f, req, path):
 * Read an HTTP request from ${f}.  Store an HTTP/1.0 request (which may be
 * identical or may be reconstructed with the same semantic meaning) in
 * ${req}, and a normalized IMDS request path in ${path}.
 */
int
request_read(FILE * f, char ** req, char ** path)
{
	char * line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	char * p;
	char * s;
	char * method;
	char * uri;
	char * val;
	char * hdr_forwarded = NULL;
	char * hdr_xforwardedfor = NULL;
	char * hdr_token = NULL;
	char * hdr_token_ttl = NULL;
	char * encpath;
	int hasbody;

	/*
	 * Read and parse the Request-Line into "<METHOD> <URI> HTTP/.*".  We
	 * don't bother checking the HTTP version or verifying that there is
	 * no trailing junk.
	 */
	if ((linelen = getline(&line, &linecap, f)) <= 0) {
		warnp("Could not read Request-Line");
		goto err0;
	}
	(void)linelen; /* This linelen is not used beyond this point. */
	if ((p = strchr(line, ' ')) == NULL) {
		warn0("Invalid Request-Line read");
		goto err1;
	} else {
		*p = '\0';
		if ((method = strdup(line)) == NULL) {
			warnp("strdup");
			goto err1;
		}
		s = &p[1];
	}
	if ((p = strchr(s, ' ')) == NULL) {
		warn0("Invalid Request-Line read");
		goto err2;
	} else {
		*p = '\0';
		if ((uri = strdup(s)) == NULL) {
			warnp("strdup");
			goto err2;
		}
		s = &p[1];
	}
	if (strncmp(s, "HTTP/", 5)) {
		warn0("Invalid Request-Line read");
		goto err3;
	}

	/* PUT/POST have bodies; GET/HEAD don't. */
	if ((strcmp(method, "PUT") == 0) ||
	    (strcmp(method, "POST") == 0))
		hasbody = 1;
	else if ((strcmp(method, "GET") == 0) ||
	    (strcmp(method, "HEAD") == 0))
		hasbody = 0;
	else	{
		/* We don't understand this request; drop it. */
		goto err3;
	}

	/* Extract a normalized path from the uri. */
	if (uri2path(uri, path))
		goto err3;

	/* Read headers. */
	while ((linelen = getline(&line, &linecap, f)) >= 0) {
		/* EOF? */
		if (linelen == 0) {
			warn0("Unexpected end of HTTP request");
			goto err4;
		}

		/* Strip trailing \r\n. */
		while (linelen) {
			if ((line[linelen - 1] != '\r') &&
			    (line[linelen - 1] != '\n'))
				break;
			line[--linelen] = '\0';
		}

		/* End of request? */
		if (linelen == 0)
			break;

		/* Split into field-name and field-value. */
		if ((p = strchr(line, ':')) == NULL) {
			warn0("Invalid HTTP header line read");
			goto err4;
		}
		*p = '\0';
		val = &p[1];

		/* Strip whitespace before and after the separator. */
		while ((*val == ' ') || (*val == '\t'))
			val++;
		while ((p > line) &&
		    ((p[-1] == ' ') || (p[-1] == '\t')))
			*p-- = '\0';

		/* Make sure nobody is trying to smuggle an EOL character. */
		if (strchr(p, '\r') != NULL) {
			warn0("HTTP header contains \\r");
			goto err4;
		}

		/* Is this a header we care about? */
#define GETHDR(name, var) do {			\
	if (strcasecmp(line, name) == 0) {	\
		free(var);			\
		var = strdup(val);		\
		if (var == NULL)		\
			goto err4;		\
	}					\
} while (0)
		GETHDR("Forwarded", hdr_forwarded);
		GETHDR("X-Forwarded-for", hdr_xforwardedfor);
		GETHDR("X-aws-ec2-metadata-token", hdr_token);
		GETHDR("X-aws-ec2-metadata-token-ttl-seconds", hdr_token_ttl);
#undef GETHDR
	}

	/* Percent-encode the request path. */
	if ((encpath = urlencode(*path)) == NULL)
		goto err4;

	/* Construct an HTTP/1.0 request. */
	if (asprintf(req,
	    "%s %s HTTP/1.0"
	    "%s%s"
	    "%s%s"
	    "%s%s"
	    "%s%s"
	    "%s"
	    "\r\nConnection: Close\r\n\r\n",
	    method, encpath,
#define DOHDR(name, var) var ? "\r\n" name ":" : "", var ? var : ""
	    DOHDR("Forwarded", hdr_forwarded),
	    DOHDR("X-Forwarded-for", hdr_xforwardedfor),
	    DOHDR("X-aws-ec2-metadata-token", hdr_token),
	    DOHDR("X-aws-ec2-metadata-token-ttl-seconds", hdr_token_ttl),
#undef DOHDR
	    hasbody ? "\r\nContent-Length:0" : "") == -1)
		goto err5;

	/* Clean up temporary allocated strings. */
	free(encpath);
	free(hdr_forwarded);
	free(hdr_xforwardedfor);
	free(hdr_token);
	free(hdr_token_ttl);
	free(uri);
	free(method);
	free(line);

	/* Success! */
	return (0);

err5:
	free(encpath);
err4:
	free(hdr_forwarded);
	free(hdr_xforwardedfor);
	free(hdr_token);
	free(hdr_token_ttl);
	free(*path);
err3:
	free(uri);
err2:
	free(method);
err1:
	free(line);
err0:
	/* Failure! */
	return (-1);
}
