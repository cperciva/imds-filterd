#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elasticarray.h"
#include "warnp.h"

#include "imds-proxy.h"

/* A single rule. */
struct rule {
	int rtype;
#define RTYPE_ANY 0
#define RTYPE_UID 1
#define RTYPE_GID 2
	id_t id;
	char * prefix;
	int allow;
};

/* IMDS access rules. */
struct imds_conf {
	struct rule * rs;
	size_t nrs;
};

ELASTICARRAY_DECL(RULELIST, rulelist, struct rule);

/* Buffer length for getpwnam_r and getgrnam_r. */
#define PWBUFLEN 4096

/* Parse a user name to a uid. */
static int
parseuid(char * p, size_t len, uid_t * u)
{
	struct passwd pwd;
	struct passwd * res;
	char buf[PWBUFLEN];
	char * s;
	char * e;

	/* Create a NUL-terminated string with the name. */
	if ((s = malloc(len + 1)) == NULL)
		goto err0;
	memcpy(s, p, len);
	s[len] = '\0';

	/* Look up the user. */
	if (getpwnam_r(s, &pwd, buf, PWBUFLEN, &res)) {
		warnp("getpwnam_r(%s)", s);
		goto err1;
	}

	/* Does the user exist? */
	if (res == NULL) {
		warn0("User not found: %s", s);
		goto err1;
	}

	/* Free the duplicated name. */
	free(s);

	/* Return the user ID. */
	*u = res->pw_uid;

	/* Success! */
	return (0);

err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

/* Parse a group name to a gid. */
static int
parsegid(char * p, size_t len, gid_t * g)
{
	struct group grp;
	struct group * res;
	char buf[PWBUFLEN];
	char * s;
	char * e;

	/* Create a NUL-terminated string with the name. */
	if ((s = malloc(len + 1)) == NULL)
		goto err0;
	memcpy(s, p, len);
	s[len] = '\0';

	/* Look up the group. */
	if (getgrnam_r(s, &grp, buf, PWBUFLEN, &res)) {
		warnp("getgrnam_r(%s)", s);
		goto err1;
	}

	/* Does the group exist? */
	if (res == NULL) {
		warn0("Group not found: %s", s);
		goto err1;
	}

	/* Free the duplicated name. */
	free(s);

	/* Return the group ID. */
	*g = res->gr_gid;

	/* Success! */
	return (0);

err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * conf_read(path):
 * Read the imds-proxy configuration file ${path} and return a state which
 * can be passed to conf_check or conf_free.
 */
struct imds_conf *
conf_read(const char * path)
{
	struct imds_conf * imdsc;
	RULELIST rs;
	struct rule r;
	FILE * f;
	char * line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	size_t i;
	char * p;
	char * sp;
	uid_t u;
	gid_t g;

	/* Open the configuration file. */
	if ((f = fopen(path, "r")) == NULL) {
		warnp("fopen(%s)", path);
		goto err0;
	}

	/* Create an elastic array of rules. */
	if ((rs = rulelist_init(0)) == NULL)
		goto err1;

	/* Read lines and construct rules. */
	while ((linelen = getline(&line, &linecap, f)) > 0) {
		/* Strip trailing EOL characters. */
		while ((linelen > 0) &&
		    ((line[linelen - 1] == '\n') ||
		     (line[linelen - 1] == '\r'))) {
			line[--linelen] = '\0';
		}

		/* Skip comments and empty lines. */
		if ((line[0] == '#') || (line[0] == '\0'))
			continue;

		/* Allow or Deny? */
		if (strncmp(line, "Deny ", 5) == 0) {
			p = &line[5];
			r.allow = 0;
		} else if (strncmp(line, "Allow ", 6) == 0) {
			p = &line[6];
			r.allow = 1;
		} else {
			goto invalid;
		}

		/* Is there a user/group restriction? */
		if (strncmp(p, "user ", 5) == 0) {
			p = &p[5];
			r.rtype = RTYPE_UID;
			if ((sp = strchr(p, ' ')) == NULL)
				goto invalid;
			if (parseuid(p, sp - p, &u))
				goto err2;
			p = &sp[1];
			r.id = u;
		} else if (strncmp(p, "group ", 6) == 0) {
			p = &p[6];
			r.rtype = RTYPE_GID;
			if ((sp = strchr(p, ' ')) == NULL)
				goto invalid;
			if (parsegid(p, sp - p, &g))
				goto err2;
			p = &sp[1];
			r.id = g;
		} else {
			r.rtype = RTYPE_ANY;
		}

		/* We should have a quoted string. */
		if ((p[0] != '"') ||
		    (strchr(&p[1], '"') != &line[linelen - 1]))
			goto invalid;

		/* Make sure that there aren't any bogus wildcards. */
		for (i = 0; p[i]; i++) {
			if (p[i] == '*') {
				/* Must follow a '/' character. */
				if (p[i - 1] != '/')
					goto invalid;

				/*
				 * Must precede a '/' character or be at the
				 * end of the string (which is nonetheless
				 * pointless, since we match prefixes).
				 */
				 if ((p[i + 1] != '/') &&
				     (p[i + 1] != '"'))
					goto invalid;
			}
		}

		/* Record the prefix string, without the endquote char. */
		if ((r.prefix = strdup(&p[1])) == NULL)
			goto err2;
		r.prefix[strlen(r.prefix) - 1] = '\0';

		/* Add this rule to our ruleset. */
		if (rulelist_append(rs, &r, 1)) {
			free(r.prefix);
			goto err2;
		}

		/* Move onto the next line. */
		continue;

invalid:
		warn0("Invalid configuration rule: %s", line);
		goto err2;

	}

	/* We should have reached EOF. */
	if (!feof(f)) {
		warnp("Error reading configuration file: %s", path);
		goto err2;
	}

	/* Create a state structure and export the list. */
	if ((imdsc = malloc(sizeof(struct imds_conf))) == NULL)
		goto err2;
	if (rulelist_export(rs, &imdsc->rs, &imdsc->nrs))
		goto err3;

	/* Success! */
	return (imdsc);

err3:
	free(imdsc);
err2:
	free(line);
	for (i = 0; i < rulelist_getsize(rs); i++)
		free(rulelist_get(rs, i)->prefix);
	rulelist_free(rs);
err1:
	fclose(f);
err0:
	/* Failure! */
	return (NULL);
}

/* Check whether the path matches. */
static int
pathmatch(const char * path, const char * prefix)
{

	/* Scan through the prefix one character at a time. */
	for (; *prefix; prefix++) {
		/* A '*' matches until the next '/' or the end. */
		if (*prefix == '*') {
			while ((*path != '/') && (*path != '\0'))
				path++;
			continue;
		}

		/* Anything else only matches itself. */
		if (*prefix != *path++)
			return (0);
	}

	/* The entire prefix matches the provided path. */
	return (1);
}

/**
 * conf_check(imdsc, path, uid, gids, ngid):
 * Check whether the specified uid/gids is allowed to make this request;
 * return nonzero if the request is allowed.
 */
int
conf_check(const struct imds_conf * imdsc, const char * path,
    uid_t uid, gid_t * gids, size_t ngid)
{
	size_t rnum, i;
	int allow = 0;

	/* Scan through the rules looking for any which match. */
	for (rnum = 0; rnum < imdsc->nrs; rnum++) {
		/* Does the id match (if relevant)? */
		if (imdsc->rs[rnum].rtype == RTYPE_UID) {
			if (imdsc->rs[rnum].id != uid)
				continue;
//			warn0("XXX UID match rule %zu", rnum);
		} else if (imdsc->rs[rnum].rtype == RTYPE_GID) {
			for (i = 0; i < ngid; i++) {
				if (imdsc->rs[rnum].id == gids[i])
					break;
			}
			if (i == ngid)
				continue;
//			warn0("XXX GID match rule %zu", rnum);
		}

		/* Does the path match? */
		if (!pathmatch(path, imdsc->rs[rnum].prefix))
			continue;

//		warn0("XXX path match rule %zu", rnum);

		/* Do what this rule says. */
		allow = imdsc->rs[rnum].allow;
	}

	/* Return status from the last matched rule. */
	return (allow);
}

/**
 * conf_free(imdsc):
 * Free the configuration state ${imdsc}.
 */
void
conf_free(struct imds_conf * imdsc)
{
	size_t rnum;

	/* Free the prefix strings. */
	for (rnum = 0; rnum < imdsc->nrs; rnum++)
		free(imdsc->rs[rnum].prefix);

	/* Free the array of rules. */
	free(imdsc->rs);

	/* Free the structure. */
	free(imdsc);
}
