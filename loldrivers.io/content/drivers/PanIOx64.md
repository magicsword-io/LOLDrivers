+++

description = ""
title = "PanIOx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PanIOx64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PanIOx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create PanIOx64.sys binPath=C:\windows\temp\PanIOx64.sys type=kernel
sc.exe start PanIOx64.sys
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

| Filename | PanIOx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0d6fef14f8e1ce5753424bd22c46b1ce">0d6fef14f8e1ce5753424bd22c46b1ce</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/814200191551faec65b21f5f6819b46c8fc227a3">814200191551faec65b21f5f6819b46c8fc227a3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6b830ea0db6546a044c9900d3f335e7820c2a80e147b0751641899d1a5aa8f74">6b830ea0db6546a044c9900d3f335e7820c2a80e147b0751641899d1a5aa8f74</a> |
| Signature | PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., GlobalSign CodeSigning CA - G2, GlobalSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/paniox64.sys.yml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
