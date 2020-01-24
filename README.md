imds-filterd
============

**`imds-filterd`** (pronounced "I M D S Filter D") is a pair of utilities
which work together to intercept and filter requests to the EC2 Instance
Metadata Service -- or theoretically any other service at 169.254.169.254:80.

It validates requests against a configured ruleset which specifies whether
given users and groups should be allowed or denied access to certain prefixes
in the Instance Metadata Service.  For example, "root" could be granted
access to everything; most unprivileged users granted access to everything
except IAM role credentials; but the www user denied access to the entire
Instance Metadata Service in order to guard against SSRF and similar attacks.

At present this code only works on FreeBSD; we hope to support other
platforms (e.g., Linux) in the future.  (Send patches!)

Code layout
-----------

```
imds-filterd/*  -- Privileged code
  main.c        -- Initialization and event loop
  netconfig.c   -- Gathers information about the network configuration (e.g.
                   where and how to access the IMDS).
  tunsetup.c    -- Creates a virtualized environment and creates tunnels used
                   to redirect packets in and out of it.
  packets.c     -- Pushes packets in and out of the virtualized environment.
  conns.c       -- Provides a mechanism for imds-proxy to connect to the IMDS.
  ident.c       -- Provides an "ident" service used by imds-proxy.
imds-proxy/*    -- Unprivileged filtering HTTP proxy
  main.c        -- Command line parsing, initialization, and connection
                   acceptance.
  conf.c        -- Reads the configuration and performs queries against it.
  http.c        -- Handles an HTTP connection (possibly forwarding it).
  ident.c       -- Uses imds-filterd to determine the source of a request.
  request.c     -- Parses an HTTP request.
  uri2path.c    -- Extracts and normalizes the path from a Request-URI.
```
