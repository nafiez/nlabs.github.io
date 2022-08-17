---
layout: post
title:  "G Data Total Security - ACLs Bypass Vulnerability"
date:   2019-03-13 05:39:03 +0800
tags:
    - CVE-2019-9742
---

Overview
--------
A weak ACLs implementation in G Data Total Security prone to vulnerable with ACLs bypass. Further investigation found the driver lack of security checks where the FILE_DEVICE_SECURE_OPEN flag is not set. The security issue has been reported to vendor (G Data) and acknowledge. 

Vulnerability Analysis
----------------------
G Data Total Security prone to vulnerable with ACLs bypass. The vulnerability found in the driver named gdwfpcd.sys. It is quite trivial to spot the issue by using DeviceTree tool. We extract the driver using the tool and spot the interpreted device characteristics empty, which is missing FILE_DEVICE_SECURE_OPEN. This means the driver didn't protect well that could allow to impersonate or create object to bypass the ACL. Screenshot below shows the driver prone to lack of ACL protection:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nafiez.github.io/master/static/img/_posts/g1.png "Screenshot broadcast")

According to Microsoft (as part of Windows security model), it is required to perform a security checks in the driver and set FILE_DEVICE_SECURE_OPEN. If developer did not set FILE_DEVICE_SECURE_OPEN, the driver are responsible for ensuring the security of its namespace. In this case, the flag is not set with ACL and this only applied only to the device, not any 'file' inside it. Any open as non-admin of \Device\gdwfpcd will fail, but if there's any open for \Device\gdwfpcd\bypass, it will succeed. Because the FILE_DEVICE_SECURE_OPEN flag is not set, the IO Manager assumes this is a file system driver, and as such, will implement its own ACLs on files and directories inside the device. A proof-of-concept can be crafted by creating a simple 
```
CreateFile("\\\\.\\gdwfpcd\\ACLBypass", 0, 0, 0, 0, 0, 0)
```
Example of the successful ACLs bypass: 
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nafiez.github.io/master/static/img/_posts/g2.png "Screenshot broadcast")

**Disclosure timeline**
```
2018-12-27 - Reported to G Data (via Support web form)
2019-01-08 - Vendor (Support team) ack and asked for more detail. Full writeup and proof-of-concept provided.
2019-01-14 - Vendor (Ralf Hilker from Security team) ack the issue and will roll out patch to customer.
2019-01-17 - Ralf provide an update to roll out patch on 11th Feb 2019. However, there's a delay for the patch release. Ralf informed that there's no change log of the fix. So it won't be visible in their website.
2019-02-15 - Follow up with Ralf. Asking for disclosure. Ralf requested to hold disclosure until 22nd Feb (wait until all customers gets an update). Agree with their decision. Fix version: https://secure.gd/dl-de-ts
2019-03-12 - Follow up with Ralf again for disclosure. They agree with it. 
2019-03-13 - CVE assigned, CVE-2019-9742
```
