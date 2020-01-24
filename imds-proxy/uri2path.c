#include <stdlib.h>
#include <string.h>

#include "hexify.h"
#include "warnp.h"

#include "imds-proxy.h"

/**
 * uri2path(uri, path):
 * Extract the path from the HTTP Request-URI ${uri}, normalize it, and
 * return it via ${path}.
 */
int
uri2path(const char * uri, char ** path)
{
	char * s;
	size_t pos, opos;
	char c;

	/*
	 * Allocate a working buffer.  We need up to 2 extra bytes due to
	 * the path normalization process.
	 */
	if ((s = malloc(strlen(uri) + 3)) == NULL)
		goto err0;

	/* Start with a '/' in the path; and at the start of the uri. */
	s[0] = '/';
	opos = 1;
	pos = 0;

	/* Advance past a scheme if present. */
	while ((c = uri[pos]) != '\0') {
		if ((c == ':') || (c == '/') || (c == '?') || (c == '#'))
			break;
		pos++;
	}
	if (c != ':') {
		/* No scheme here; go back to the start. */
		pos = 0;
	}

	/* Advance past a host if present. */
	if ((uri[pos] == '/') && (uri[pos + 1] == '/')) {
		pos += 2;
		while ((c = uri[pos]) != '\0') {
			if ((c == '/') || (c == '?') || (c == '#'))
				break;
			pos++;
		}
	}

	/* Copy until we hit a query string or fragment. */
	while ((c = uri[pos]) != '\0') {
		if ((c == '?') || (c == '#'))
			break;
		s[opos++] = c;
		pos++;
	}

	/*
	 * Append a '/' to the path; we'll strip it later but this makes
	 * handling '.' and '..' path segments easier.  NUL-terimate the
	 * string.
	 */
	s[opos++] = '/';
	s[opos] = '\0';

	/* Scan through the path, undoing any percent-encoding. */
	for (opos = pos = 0; (c = s[pos]) != '\0'; pos++) {
		if (c == '%') {
			if ((s[pos + 1] == '\0') || (s[pos + 2] == '\0') ||
			     unhexify(&s[pos + 1], (uint8_t *)&c, 1)) {
				/* Invalid percent-encoding. */
				warn0("Invalid URI");
				goto err1;
			}
			pos += 2;
		}
		s[opos] = c;
	}

	/*
	 * Collapse empty, dot, and dotdot path segments.  Each time through
	 * the loop, pos and opos point to the character *after* the last '/'
	 * seen.
	 */
	opos = pos = 1;
	while (s[pos] != '\0') {
		/* "//" -> "/". */
		if (s[pos] == '/') {
			pos += 1;
			continue;
		}

		/* "/./" -> "/". */
		if ((s[pos] == '.') && (s[pos + 1] == '/')) {
			pos += 2;
			continue;
		}

		/* If we have "/../", remove the last segment, if any. */
		if ((s[pos] == '.') && (s[pos + 1] == '.') &&
		    (s[pos + 2] == '/')) {
			pos += 3;
			if (opos == 1)
				continue;
			do {
				opos--;
			} while ((opos > 1) && (s[opos - 1] != '/'));
			continue;
		}

		/* Copy the next segment up to and including '/'. */
		do {
			s[opos++] = s[pos++];
		} while (s[pos - 1] != '/');
	}
	s[opos] = '\0';

	/*
	 * Remove any trailing '/' character, unless it's the entire string.
	 * This may be one we added above, or it may be one which was part of
	 * the original request; there can't be more than one since a pair
	 * of consecutive '/' characters would have been collapsed above.
	 */
	if (opos > 1)
		s[--opos] = '\0';

	/* Return the string. */
	*path = s;

	/* Success! */
	return (0);

err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}
