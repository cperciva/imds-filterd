#define __BSD_VISIBLE	1	/* Needed for netinet/ headers. */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_var.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asprintf.h"
#include "warnp.h"

#include "imds-filterd.h"

/**
 * makejail(name, jid):
 * Create a jail with name and hostname ${name} which is persistent and has
 * its own virtualized network stack.  Return the jail id via ${jid}.
 */
int
makejail(const char * name, int * jid)
{

	if ((*jid = jail_setv(JAIL_CREATE,
	    "name", name,
	    "host.hostname", name,
	    "persist", NULL,
	    "vnet", NULL,
	    NULL)) == -1) {
		warnp("jail_setv");
		return (-1);
	}

	/* Success! */
	return (0);
}

/**
 * rmjail(jid):
 * Remove the jail with the jail ID ${jid}.
 */
int
rmjail(int jid)
{

	return (jail_remove(jid));
}

/**
 * createtun(nam, fd):
 * Create a tunnel device, and assign it the interface name ${nam}.  Open it
 * and return a file descriptor via ${fd}.
 */
static int
createtun(const char * nam, int * fd)
{
	int s;
	struct ifreq ifr;
	char * devnam;
	char * tmpnam;

	/* Create a socket for use in making ioctl requests. */
	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) == -1) {
		warnp("socket(AF_LOCAL, SOCK_DGRAM, 0)");
		goto err0;
	}

	/* Make sure the tunnel doesn't already exist. */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nam, sizeof(ifr.ifr_name));
	if (!ioctl(s, SIOCGIFFLAGS, &ifr)) {
		warn0("Interface \"%s\" already exists!", nam);
		goto err1;
	}
	if (errno != ENXIO) {
		warn0("ioctl(SIOCGIFFLAGS)");
		goto err1;
	}

	/* Create a tun device. */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, "tun", sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFCREATE, &ifr)) {
		warnp("ioctl(SIOCIFCREATE)");
		goto err1;
	}

	/* Construct the path to the device node. */
	if (asprintf(&devnam, "/dev/%s", ifr.ifr_name) == -1) {
		warnp("asprintf");
		goto err2;
	}

	/* Open the device node. */
	if ((*fd = open(devnam, O_RDWR)) == -1) {
		warnp("open(%s)", devnam);
		goto err3;
	}

	/*
	 * Assign a name to make the tunnel's purpose clear to users.  Copy
	 * the requested name into a temporary buffer, because ifr_data is
	 * specified as non-const; this is probably unnecessary, but it's
	 * just possible that the kernel would want to write to ifr_data...
	 */
	if ((tmpnam = strdup(nam)) == NULL)
		goto err4;
	ifr.ifr_data = tmpnam;
	if (ioctl(s, SIOCSIFNAME, &ifr)) {
		warnp("ioctl(SIOCSIFNAME)");
		goto err5;
	}
	free(tmpnam);

	/* Free the path to the device node. */
	free(devnam);

	/* Close the socket we created for ioctls. */
	close(s);

	/* Success! */
	return (0);

err5:
	free(tmpnam);
err4:
	close(*fd);
err3:
	free(devnam);
err2:
	/* Destroying using the real name -- interface hasn't renamed yet. */
	ioctl(s, SIOCIFDESTROY, &ifr);
err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * jailtun(nam, jid):
 * Place the tunnel interface ${tun} into jail ID ${jid}.
 */
static int
jailtun(const char * nam, int jid)
{
	int s;
	struct ifreq ifr;

	/* Create a socket for use in making ioctl requests. */
	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) == -1) {
		warnp("socket(AF_LOCAL, SOCK_DGRAM, 0)");
		goto err0;
	}

	/* Place the interface into the jail. */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nam, sizeof(ifr.ifr_name));
	ifr.ifr_jid = jid;
	if (ioctl(s, SIOCSIFVNET, &ifr)) {
		warnp("ioctl(SIOCSIFVNET)");
		goto err1;
	}

	/* Close the socket we created for ioctls. */
	close(s);

	/* Success! */
	return (0);

err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * unjailtun(nam, jid):
 * Remove the tunnel interface ${nam} from the jail ID ${jid}.
 */
static int
unjailtun(const char * nam, int jid)
{
	int s;
	struct ifreq ifr;

	/* Create a socket for use in making ioctl requests. */
	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) == -1) {
		warnp("socket(AF_LOCAL, SOCK_DGRAM, 0)");
		goto err0;
	}

	/* Remove the interface from the jail. */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nam, sizeof(ifr.ifr_name));
	ifr.ifr_jid = jid;
	if (ioctl(s, SIOCSIFRVNET, &ifr)) {
		warnp("ioctl(SIOCSIFRVNET)");
		goto err1;
	}

	/* Close the socket we created for ioctls. */
	close(s);

	/* Success! */
	return (0);

err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * destroytun(nam):
 * Destroy the tunnel interface ${nam}.
 */
static int
destroytun(const char * nam)
{
	int s;
	struct ifreq ifr;

	/* Create a socket for use in making ioctl requests. */
	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) == -1) {
		warnp("socket(AF_LOCAL, SOCK_DGRAM, 0)");
		goto err0;
	}

	/* Destroy the tun device. */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nam, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFDESTROY, &ifr)) {
		warnp("ioctl(SIOCIFDESTROY)");
		goto err1;
	}

	/* Close the socket we created for ioctls. */
	close(s);

	/* Success! */
	return (0);

err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * settunip(nam, local, remote):
 * Set the tunnel interface ${nam} to be a tunnel from ${local} to ${remote}.
 */
static int
settunip(const char * nam, struct sockaddr_in * local,
    struct sockaddr_in * remote)
{
	struct in_aliasreq ifra;
	int s;

	/* Create a socket for use in making ioctl requests. */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		warnp("socket(AF_INET, SOCK_DGRAM, 0)");
		goto err0;
	}

	/* Set addresses on the tunnel interface. */
	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, nam, sizeof(ifra.ifra_name));
	ifra.ifra_addr = *local;
	ifra.ifra_dstaddr = *remote;
	if (ioctl(s, SIOCAIFADDR, &ifra)) {
		warnp("ioctl(SIOCAIFADDR)");
		goto err1;
	}

	/* Close socket used for ioctls. */
	close(s);

	/* Success! */
	return (0);

err1:
	close(s);
err0:
	/* Failure! */
	return (-1);
}

/**
 * setjailtunip(nam, local, remote, jid):
 * Set the tunnel interface ${nam} inside the jail ${jid} to be a tunnel
 * from ${local} to ${remote}.
 */
static int
setjailtunip(const char * nam, struct sockaddr_in * local,
    struct sockaddr_in * remote, int jid)
{
	pid_t pid;
	int status;

	/* Fork off a child which can work in the jail. */
	switch (pid = fork()) {
	case -1:
		/* Fork failed. */
		warnp("fork");
		goto err0;
	case 0:
		/* Child process -- enter the jail and set IP addresses. */
		if (jail_attach(jid)) {
			warnp("jail_attach");
			_exit(1);
		}
		if (settunip(nam, local, remote))
			_exit(1);
		_exit(0);
	default:
		/* Parent process. */
		break;
	}

	/* Wait for the jailed child to exit. */
	if (waitpid(pid, &status, 0) != pid) {
		warnp("waitpid");
		goto err0;
	}

	/* Check that the jailed child succeeded. */
	if ((!WIFEXITED(status)) || (WEXITSTATUS(status) != 0))
		goto err0;

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

/**
 * tunsetup(tunin, tunout, srcaddr, dstaddr, jid):
 * Set up a pair of tunnels:
 * 1. From ${srcaddr} to ${dstaddr}, named "imds-tun", with file descriptor
 * returned via ${tunin}; and
 * 2. From ${dstaddr} to ${srcaddr}, named "imds-tunout", placed inside jail
 * ID ${jid}, with file descriptor returned via ${tunout}.
 */
int
tunsetup(int * tunin, int * tunout, struct sockaddr_in * srcaddr,
    struct sockaddr_in * dstaddr, int jid)
{

	if (createtun("imds-tun", tunin)) {
		warnp("Could not create imds-tun");
		goto err0;
	}
	if (createtun("imds-tunout", tunout)) {
		warnp("Could not create imds-tunout");
		goto err1;
	}
	if (jailtun("imds-tunout", jid)) {
		warnp("Could not place imds-tunout into jail");
		goto err2;
	}
	if (settunip("imds-tun", srcaddr, dstaddr)) {
		warnp("Could not initialize imds-tun");
		goto err3;
	}
	if (setjailtunip("imds-tunout", dstaddr, srcaddr, jid)) {
		warnp("Could not initialize imds-tunout");
		goto err3;
	}

	/* Success! */
	return (0);

err3:
	unjailtun("imds-tunout", jid);
err2:
	close(*tunout);
	destroytun("imds-tunout");
err1:
	close(*tunin);
	destroytun("imds-tun");
err0:
	/* Failure! */
	return (-1);
}

/**
 * tuncleanup(tunin, tunout, jid):
 * Clean up the work done by tunsetup.
 */
void
tuncleanup(int tunin, int tunout, int jid)
{

	/* Cleanup path; no point handling errors, but report them. */
	if (close(tunout))
		warnp("close");
	if (close(tunin))
		warnp("close");
	if (unjailtun("imds-tunout", jid))
		warnp("Can't remove imds-tunout from jail");
	if (destroytun("imds-tunout"))
		warnp("Can't destroy imds-tunout");
	if (destroytun("imds-tun"))
		warnp("Can't destroy imds-tun");
}
