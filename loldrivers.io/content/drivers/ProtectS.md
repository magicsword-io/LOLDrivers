+++

description = ""
title = "ProtectS.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ProtectS.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

ProtectS.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ProtectS.sys binPath=C:\windows\temp\ProtectS.sys type=kernel
sc.exe start ProtectS.sys
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

| Filename | ProtectS.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9d58f640c7295952b71bdcb456cae37213baccdcd3032c1e3aeb54e79081f395">9d58f640c7295952b71bdcb456cae37213baccdcd3032c1e3aeb54e79081f395</a> |
| Signature | -   || Filename | ProtectS.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4a9093e8dbcb867e1b97a0a67ce99a8511900658f5201c34ffb8035881f2dbbe">4a9093e8dbcb867e1b97a0a67ce99a8511900658f5201c34ffb8035881f2dbbe</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/protects.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
