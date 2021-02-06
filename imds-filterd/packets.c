#define __BSD_VISIBLE	1	/* Needed for net/ headers. */
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/bpf.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "asprintf.h"
#include "events.h"
#include "warnp.h"

#include "imds-filterd.h"

/* Maximum length of an IPv4 packet. */
#define MAXPACKET 65535

/* State for outward packet path handling. */
struct outpath_state {
	int rdtun;
	int wrtun;
	int extif;
	in_addr_t dstaddr;
	uint16_t dstport;
	uint8_t etherframe[14 + MAXPACKET];
};

static int
outpkt(void * cookie)
{
	struct outpath_state * os = cookie;
	struct ip * pkt_ip;
	struct tcphdr * pkt_tcp;
	ssize_t rlen, wlen;
	in_addr_t srcaddr, dstaddr;
	uint16_t srcport, dstport;

	/* Read a packet. */
	rlen = read(os->rdtun, &os->etherframe[14], MAXPACKET);
	if (rlen == -1) {
		warnp("Error reading packet from tunnel device");
		goto err0;
	}
	if (rlen == 0) {
		warn0("Unexpected EOF from tunnel device");
		goto err0;
	}

	/* Check that we have an IPv4 packet. */
	if ((size_t)rlen < sizeof(struct ip))
		goto readmore;
	pkt_ip = (struct ip *)(&os->etherframe[14]);
	if (pkt_ip->ip_v != 4)
		goto readmore;

	/* Make sure that this is a TCP packet. */
	if (pkt_ip->ip_p != IPPROTO_TCP)
		goto readmore;
	if ((size_t)rlen < pkt_ip->ip_hl * 4 + sizeof(struct tcphdr))
		goto readmore;
	pkt_tcp = (struct tcphdr *)(&os->etherframe[14 + pkt_ip->ip_hl * 4]);

	/* Extract source and destination IP addresses and port numbers. */
	srcaddr = ntohl(pkt_ip->ip_src.s_addr);
	dstaddr = ntohl(pkt_ip->ip_dst.s_addr);
	srcport = ntohs(pkt_tcp->th_sport);
	dstport = ntohs(pkt_tcp->th_dport);

	/*
	 * If the source and destination match one of our own connections,
	 * let it through to the external interface; otherwise, redirect the
	 * IP packet through a tunnel into the jail.
	 */
	if (conns_isours(srcaddr, srcport) &&
	    (dstaddr == os->dstaddr) && (dstport == os->dstport)) {
		/* Write the ethernet frame over the external interface. */
		wlen = rlen + 14;
		if (write(os->extif, os->etherframe, (size_t)wlen) != wlen) {
			warnp("Error writing ethernet frame");
			goto err0;
		}
	} else {
		/* Write the IPv4 packet into the other tunnel. */
		if (write(os->wrtun, &os->etherframe[14], (size_t)rlen)
		    != rlen) {
			warnp("Error writing packet into tunnel");
			goto err0;
		}
	}

readmore:
	/* Wait for the next packet to arrive. */
	if (events_network_register(outpkt, os, os->rdtun,
	    EVENTS_NETWORK_OP_READ)) {
		warnp("Cannot register packet read callback");
		goto err0;
	}

	/* Success! */
	return (0);

err0:
	/* Fatal error! */
	return (-1);
}

/**
 * outpath(tunin, tunout, dstaddr, ifname, srcmac, gwmac):
 * Read packets from ${tunin} and either write them to ${tunout} or wrap them
 * into ethernet frames and send them via ${ifname}.
 */
int
outpath(int tunin, int tunout, struct sockaddr_in * dstaddr,
    const char * ifname, uint8_t srcmac[6], uint8_t gwmac[6])
{
	struct outpath_state * os;
	struct ifreq ifr;

	/* Allocate state structure. */
	if ((os = malloc(sizeof(struct outpath_state))) == NULL)
		goto err0;
	os->rdtun = tunin;
	os->wrtun = tunout;
	os->dstaddr = ntohl(dstaddr->sin_addr.s_addr);
	os->dstport = ntohs(dstaddr->sin_port);

	/* Open BPF. */
	if ((os->extif = open("/dev/bpf", O_WRONLY)) == -1) {
		warnp("open(/dev/bpf)");
		goto err1;
	}

	/* Bind to the external network interface. */
	memset(&ifr, 0, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(os->extif, BIOCSETIF, &ifr)) {
		warnp("ioctl(BIOCSETIF)");
		goto err2;
	}

	/* Assemble ethernet frame header. */
	memcpy(&os->etherframe[0], gwmac, 6);
	memcpy(&os->etherframe[6], srcmac, 6);
	os->etherframe[12] = 0x08;
	os->etherframe[13] = 0x00;

	/* Get a callback when a packet arrives over tunin. */
	if (events_network_register(outpkt, os, os->rdtun,
	    EVENTS_NETWORK_OP_READ)) {
		warnp("Cannot register packet read callback");
		goto err2;
	}

	/* Success! */
	return (0);

err2:
	close(os->extif);
err1:
	free(os);
err0:
	/* Failure! */
	return (-1);
}

/* State for inward packet path handling. */
struct inpath_state {
	int rdtun;
	int wrtun;
	uint8_t buf[MAXPACKET];
};

static int
inpkt(void * cookie)
{
	struct inpath_state * is = cookie;
	ssize_t rlen;

	/* Read a packet. */
	rlen = read(is->rdtun, is->buf, MAXPACKET);
	if (rlen == -1) {
		warnp("Error reading packet from tunnel device");
		goto err0;
	}
	if (rlen == 0) {
		warn0("Unexpected EOF from tunnel device");
		goto err0;
	}

	/* Write the IPv4 packet into the other tunnel. */
	if (write(is->wrtun, is->buf, (size_t)rlen) != rlen) {
		warnp("Error writing packet into tunnel");
		goto err0;
	}

	/* Wait for the next packet to arrive. */
	if (events_network_register(inpkt, is, is->rdtun,
	    EVENTS_NETWORK_OP_READ)) {
		warnp("Cannot register packet read callback");
		goto err0;
	}

	/* Success! */
	return (0);

err0:
	/* Fatal error! */
	return (-1);
}

/**
 * inpath(tunin, tunout):
 * Read packets from ${tunout} and write them to ${tunin}.
 */
int
inpath(int tunin, int tunout)
{
	struct inpath_state * is;

	/* Allocate state structure. */
	if ((is = malloc(sizeof(struct inpath_state))) == NULL)
		goto err0;
	is->rdtun = tunout;
	is->wrtun = tunin;

	/* Get a callback when a packet arrives over tunout. */
	if (events_network_register(inpkt, is, is->rdtun,
	    EVENTS_NETWORK_OP_READ)) {
		warnp("Cannot register packet read callback");
		goto err1;
	}

	/* Success! */
	return (0);

err1:
	free(is);
err0:
	/* Failure! */
	return (-1);
}
