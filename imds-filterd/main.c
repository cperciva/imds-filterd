#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemonize.h"
#include "events.h"
#include "warnp.h"

#include "imds-filterd.h"

#define IMDSIP "169.254.169.254"

static sig_atomic_t got_sigterm = 0;

static void
sigterm_handler(int signo)
{

	(void)signo; /* UNUSED */

	/* We've received a signal. */
	got_sigterm = 1;

	/* Stop handling events. */
	events_interrupt();
}

int
main(int argc, char * argv[])
{
	char * ifname;
	struct sockaddr_in srcaddr;
	struct sockaddr_in gwaddr;
	struct sockaddr_in dstaddr;
	uint8_t srcmac[6];
	uint8_t gwmac[6];
	int jid;
	int tunin;
	int tunout;

	(void)argc; /* UNUSED */
	(void)argv; /* UNUSED */

	WARNP_INIT;

	/* Construct a sockaddr for the IMDS address. */
	memset(&dstaddr, 0, sizeof(dstaddr));
	dstaddr.sin_len = sizeof(dstaddr);
	dstaddr.sin_family = AF_INET;
	dstaddr.sin_addr.s_addr = inet_addr(IMDSIP);
	dstaddr.sin_port = htons(80);

	/*
	 * Look up the interface and associated local address to be used for
	 * making connections to the Instance Metadata Service.
	 */
	if (netconfig_getif(&srcaddr, &gwaddr, dstaddr.sin_addr.s_addr,
	    &ifname)) {
		warnp("Could not find route to IMDS");
		goto err0;
	}

	/*
	 * Look up the MAC addresses for our external interface and for the
	 * gateway we use for accessing the Instance Metadata Service.
	 */
	if (netconfig_getmac(&srcaddr, srcmac)) {
		warnp("Could not look up MAC address for interface");
		goto err0;
	}
	if (netconfig_getmac(&gwaddr, gwmac)) {
		warnp("Could not look up MAC address for gateway");
		goto err0;
	}

	/* Create a jail for the IMDS filtering proxy. */
	if (makejail("imds", &jid)) {
		warnp("Failed to create jail");
		goto err0;
	}

	/* Create tunnels in and out of the jail. */
	if (tunsetup(&tunin, &tunout, &srcaddr, &dstaddr, jid)) {
		warnp("Failed to set up tunnel devices");
		goto err1;
	}

	/*
	 * Read packets destined for the Instance Metadata Service and either
	 * forward them into the jail or pass them out the network interface.
	 */
	if (outpath(tunin, tunout, &dstaddr, ifname, srcmac, gwmac)) {
		warnp("Failed to set up packet forwarding");
		goto err2;
	}

	/* Read packets coming out of the jail and pass them to the host. */
	if (inpath(tunin, tunout)) {
		warnp("Failed to set up packet forwarding");
		goto err2;
	}

	/* Accept connections from the proxy and forward them out. */
	if (conns_setup("/var/run/imds.sock", "[" IMDSIP "]:80")) {
		warnp("Failed to set up connection forwarding");
		goto err2;
	}

	/* Answer TCP connection ownership queries. */
	if (ident_setup("/var/run/imds-ident.sock")) {
		warnp("Failed to set up connection identification");
		goto err3;
	}

	/*
	 * Catch SIGTERM; this allows us to clean up our tunnels and jail
	 * if the user wants us to stop running.
	 */
	if (signal(SIGTERM, sigterm_handler) == SIG_ERR) {
		warnp("signal(SIGTERM)");
		goto err4;
	}

	/* Daemonize. */
	if (daemonize("/var/run/imds-filterd.pid")) {
		warnp("daemonize");
		goto err4;
	}

	/* Loop until an error occurs or we get SIGTERM. */
	while (got_sigterm == 0) {
		if (events_run()) {
			warnp("Error in event loop");
			break;
		}
	}

	/* Clean up the pidfile, sockets, tunnels and jail. */
	unlink("/var/run/imds-filterd.pid");
	unlink("/var/run/imds-ident.sock");
	unlink("/var/run/imds.sock");
	tuncleanup(tunin, tunout, jid);
	rmjail(jid);

	exit(0);

err4:
	unlink("/var/run/imds-ident.sock");
err3:
	unlink("/var/run/imds.sock");
err2:
	tuncleanup(tunin, tunout, jid);
err1:
	rmjail(jid);
err0:
	exit(1);
}
