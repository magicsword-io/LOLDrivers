+++

description = ""
title = "ASIO32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ASIO32.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

ASIO32.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ASIO32.sys binPath=C:\windows\temp\ASIO32.sys type=kernel
sc.exe start ASIO32.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | ASIO32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d569d4bab86e70efbcdfdac9d822139d6f477b7c">d569d4bab86e70efbcdfdac9d822139d6f477b7c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | ASIO32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/80fa962bdfb76dfcb9e5d13efc38bb3d392f2e77">80fa962bdfb76dfcb9e5d13efc38bb3d392f2e77</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | ASIO32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5a7dd0da0aee0bdedc14c1b7831b9ce9178a0346">5a7dd0da0aee0bdedc14c1b7831b9ce9178a0346</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | ASIO32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1acc7a486b52c5ee6619dbdc3b4210b5f48b936f">1acc7a486b52c5ee6619dbdc3b4210b5f48b936f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | ASIO32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/55ab7e27412eca433d76513edc7e6e03bcdd7eda">55ab7e27412eca433d76513edc7e6e03bcdd7eda</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | ASIO32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1e7c241b9a9ea79061b50fb19b3d141dee175c27">1e7c241b9a9ea79061b50fb19b3d141dee175c27</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asio32.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
