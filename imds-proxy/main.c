#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemonize.h"
#include "getopt.h"
#include "setuidgid.h"
#include "sock.h"
#include "warnp.h"

#include "imds-proxy.h"

/* Connection parameters. */
struct cstate {
	int s;
	struct sock_addr ** sas_t;
	struct sock_addr ** sas_id;
	struct imds_conf * imdsc;
};

/* Handle the connection. */
static void *
handleconn(void * cookie)
{
	struct cstate * cs = cookie;

	/* Do the work for this connection. */
	http_proxy(cs->s, cs->sas_t, cs->sas_id, cs->imdsc);

	/* Free the state structure. */
	free(cs);

	/* We're done. */
	return (NULL);
}

static void
usage(void)
{

	fprintf(stderr, "usage: imds-proxy [-f <conffile>] [-p <pidfile>]\n"
	    "    [-u <user> | <:group> | <user:group>]\n");
	exit(1);
}

int
main(int argc, char * argv[])
{
	struct sock_addr ** sas_t;
	struct sock_addr ** sas_id;
	struct imds_conf * imdsc;
	struct cstate * cs;
	struct sockaddr_in sin;
	const char * ch;
	const char * opt_f = NULL;
	const char * opt_p = NULL;
	const char * opt_u = NULL;
	pthread_t thr;
	int s;
	int rc;
	int one = 1;

	WARNP_INIT;

	/* Parse command line. */
	while ((ch = GETOPT(argc, argv)) != NULL) {
		GETOPT_SWITCH(ch) {
		GETOPT_OPTARG("-f"):
		GETOPT_OPTARG("--conffile"):
			if (opt_f)
				usage();
			opt_f = optarg;
			break;
		GETOPT_OPTARG("-p"):
		GETOPT_OPTARG("--pidfile"):
			if (opt_p)
				usage();
			opt_p = optarg;
			break;
		GETOPT_OPTARG("-u"):
		GETOPT_OPTARG("--uidgid"):
			if (opt_u)
				usage();
			opt_u = optarg;
			break;
		GETOPT_MISSING_ARG:
			warn0("Missing argument to %s", ch);
			usage();
		GETOPT_DEFAULT:
			warn0("illegal option -- %s", ch);
			usage();
		}
	}

	/* Check for unused arguments. */
	if (argc > optind)
		usage();

	/* Default configuration file. */
	if (opt_f == NULL)
		opt_f = "/usr/local/etc/imds.conf";

	/* Default pidfile. */
	if (opt_p == NULL)
		opt_p = "/var/run/imds-proxy.pid";

	/* Target address. */
	if ((sas_t = sock_resolve("/var/run/imds.sock")) == NULL) {
		warnp("sock_resolve");
		goto err0;
	}

	/* Ident socket. */
	if ((sas_id = sock_resolve("/var/run/imds-ident.sock")) == NULL) {
		warnp("sock_resolve");
		goto err1;
	}

	/* Read the configuration file. */
	if ((imdsc = conf_read(opt_f)) == NULL) {
		warnp("Could not read configuration file: %s", opt_f);
		goto err2;
	}

	/* Bind to 0.0.0.0:80 and accept connections. */
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(80);
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		warnp("socket");
		goto err3;
	}
	/* Set SO_REUSEADDR. */
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
		warnp("setsockopt(SO_REUSEADDR)");
		goto err4;
	}
	if (bind(s, (struct sockaddr *)&sin, sin.sin_len)) {
		warnp("bind");
		goto err4;
	}
	if (listen(s, 10)) {
		warnp("listen");
		goto err4;
	}

	/* Daemonize. */
	if (daemonize(opt_p)) {
		warnp("daemonize");
		goto err4;
	}

	/* Drop privileges (if applicable). */
	if (opt_u && setuidgid(opt_u, SETUIDGID_SGROUP_LEAVE_WARN)) {
		warnp("Failed to drop privileges");
		goto err4;
	}

	/* Accept connections until an error occurs. */
	do {
		if ((cs = malloc(sizeof(struct cstate))) == NULL) {
			warnp("malloc");
			goto die;
		}
		while ((cs->s = accept(s, NULL, NULL)) == -1) {
			if (errno == EINTR)
				continue;
			warnp("accept");
			goto die;
		}
		cs->sas_t = sas_t;
		cs->sas_id = sas_id;
		cs->imdsc = imdsc;
		if ((rc = pthread_create(&thr, NULL, handleconn, cs)) != 0) {
			warn0("pthread_create: %s", strerror(rc));
			goto die;
		}
	} while (1);

	/* NOTREACHED */

die:
	/*-
	 * Theoretically we might want to run
	 * close(cs->s);
	 * free(cs);
	 * and then continue with other cleanup; but at this point it's
	 * possible that threads we spawned are still running, and we need
	 * to avoid freeing memory out from underneath them -- so instead
	 * we just exit without worrying about cleaning up.
	 */
	exit(1);
err4:
	close(s);
err3:
	conf_free(imdsc);
err2:
	sock_addr_freelist(sas_id);
err1:
	sock_addr_freelist(sas_t);
err0:
	exit(1);
}
