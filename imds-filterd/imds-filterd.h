#ifndef IMDS_FILTER_H
#define IMDS_FILTER_H

#include <netinet/in.h>

/**
 * netconfig_getif(srcaddr, gwaddr, host, ifname):
 * Find the IPv4 route used for sending packets to ${host}; return via
 * ${ifname}, ${gwaddr}, and ${srcaddr} the name of the network interface,
 * the gateway, and the appropriate source IPv4 address.
 */
int netconfig_getif(struct sockaddr_in *, struct sockaddr_in *,
    in_addr_t, char **);

/*
 * netconfig_getmac(host, mac):
 * Look up the MAC address associated with the IPv4 address ${host} and
 * return it via ${mac}.  Note that this can fail if ${host} is not in the
 * operating system's ARP cache.
 */
int netconfig_getmac(struct sockaddr_in *, uint8_t[6]);

/**
 * makejail(name, jid):
 * Create a jail with name and hostname ${name} which is persistent and has
 * its own virtualized network stack.  Return the jail id via ${jid}.
 */
int makejail(const char *, int *);

/**
 * rmjail(jid):
 * Remove the jail with the jail ID ${jid}.
 */
int rmjail(int);

/**
 * tunsetup(tunin, tunout, srcaddr, dstaddr, jid):
 * Set up a pair of tunnels:
 * 1. From ${srcaddr} to ${dstaddr}, named "imds-tun", with file descriptor
 * returned via ${tunin}; and
 * 2. From ${dstaddr} to ${srcaddr}, named "imds-tunout", placed inside jail
 * ID ${jid}, with file descriptor returned via ${tunout}.
 */
int tunsetup(int *, int *, struct sockaddr_in *, struct sockaddr_in *, int);

/**
 * tuncleanup(tunin, tunout, jid):
 * Clean up the work done by tunsetup.
 */
void tuncleanup(int, int, int);

/**
 * outpath(tunin, tunout, dstaddr, ifname, srcmac, gwmac):
 * Read packets from ${tunin} and either write them to ${tunout} or wrap them
 * into ethernet frames and send them via ${ifname}.
 */
int outpath(int, int, struct sockaddr_in *, const char *,
    uint8_t[6], uint8_t[6]);

/**
 * inpath(tunin, tunout):
 * Read packets from ${tunout} and write them to ${tunin}.
 */
int inpath(int, int);

/**
 * conns_setup(path, dstaddr):
 * Create a socket at ${path}.  Forward data between incoming connections and
 * TCP connection to ${dstaddr}.
 */
int conns_setup(const char *, const char *);

/**
 * conns_isours(srcaddr, srcport):
 * Return nonzero if one of our connections to the target has source address
 * srcaddr:srcport.
 */
int conns_isours(in_addr_t, uint16_t);

/**
 * ident_setup(path):
 * Create a socke at ${path}.  Receive connections and read 12 bytes
 * [4 byte src IP][2 byte src port][4 byte dst IP][2 byte dst port]
* (in network byte order) then write back "uid\ngid[,gid]*\n".
  */
int ident_setup(const char *);

#endif /* !IMDS_FILTER_H */
