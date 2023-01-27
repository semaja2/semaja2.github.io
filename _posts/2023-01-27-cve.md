---
title: CVE-2022-44565 - UBNT AirOS - Improper Access Validation
tags: research cve security
author: Andrew
---

Kicking off the new year, is my first offical bug bounty and CVE that was reported early last year.

## Vulnerability

Whilst investigating the available API endpoints on the UBNT AirMAC AC devices, it appeared a bug was introduced that disabled the access validation if a trailing `/` was added to the URI for the various API endpoints.

This impacts at least the following endpoints;

-   /status.cgi
-   /signal.cgi
-   /glogo.cgi
-   /hist-stats.cgi

**Auth Required**
```curl -k https://192.168.1.20/status.cgi``` 

**No Auth Required**
```curl -k https://192.168.1.20/status.cgi/```

![](/assets/posts/2023-01-27/2023-01-27-cve.gif)

## Impact

Information disclosure, may contain sensitive information such as but not limited to;

-   IP Address of connected stations
-   MAC Address of connected stations
-   Firmware versions of both AP and connected stations
-   Hostnames of connected stations (WISPs may use customer name/address as hostnames)
-   Resource information of AP and connected stations

## Investigation
Reviewing the various firmware versions it was determined this bug was introduced in 8.7.4, analysis of this firmware indicated the API endpoints are compiled LUA scripts and the lighttpd server version was upgraded.


## Outcomes
After submitting the bug report to UBNT they began to patch all impacted products and was fully resolved and published on the 7th December 2022 in the [Security Advisory Bulletin 027](https://community.ui.com/releases/Security-Advisory-Bulletin-027-027/123e4577-9f00-4777-abe1-64a1d56fee05)

It was also discovered that this issue impacted the airFiber 60 and GBE product lines as well

**Affected Products:**

airMAX AC (8.7.4 - 8.7.11)

airFiber 60/LR

airFiber 60 XG/HD

GBE

**Mitigation:**

Update your airMAX AC to **Version 8.7.11 or later**.

Update your airFiber 60/LR to **Version 2.6.2 or later**.

Update your airFiber 60 XG/HD to **Version 1.0.0 or later**.

Update your GBE to **Version 1.4.1 or later**.
