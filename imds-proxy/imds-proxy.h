#ifndef IMDS_PROXY_H
#define IMDS_PROXY_H

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

/* Opaque type. */
struct sock_addr;
struct imds_conf;

/**
 * http_proxy(s, dst, id, imdsc):
 * Read an HTTP request from the socket ${s} and forward it to address ${dst},
 * after querying ${id} about the owner of the incoming connection and
 * checking against the ruleset ${imdsc}.
 */
void http_proxy(int, struct sock_addr * const *, struct sock_addr * const *,
    const struct imds_conf *);

/**
 * request_read(f, req, path):
 * Read an HTTP request from ${f}.  Store an HTTP/1.0 request (which may be
 * identical or may be reconstructed with the same semantic meaning) in
 * ${req}, and a normalized IMDS request path in ${path}.
 */
int request_read(FILE *, char **, char **);

/**
 * uri2path(uri, path):
 * Extract the path from the HTTP Request-URI ${uri}, normalize it, and
 * return it via ${path}.
 */
int uri2path(const char *, char **);

/**
 * ident(s, id, uid, gids, ngid):
 * Query ${id} about the ownership of the process holding the other end of
 * the socket ${s}; return the user ID via ${uid}, a malloced array of group
 * IDs via ${gids}, and the number of group IDs via ${ngid}.
 */
int ident(int, struct sock_addr * const *, uid_t *, gid_t **, size_t *);

/**
 * conf_read(path):
 * Read the imds-proxy configuration file ${path} and return a state which
 * can be passed to conf_check or conf_free.
 */
struct imds_conf * conf_read(const char *);

/**
 * conf_check(imdsc, path, uid, gids, ngid):
 * Check whether the specified uid/gids is allowed to make this request;
 * return nonzero if the request is allowed.
 */
int conf_check(const struct imds_conf *, const char *,
    uid_t, gid_t *, size_t);

/**
 * conf_free(imdsc):
 * Free the configuration state ${imdsc}.
 */
void conf_free(struct imds_conf *);

#endif /* !IMDS_PROXY_H */
