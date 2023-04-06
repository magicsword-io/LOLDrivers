+++

description = ""
title = "PanIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PanIO.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PanIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create PanIO.sys binPath=C:\windows\temp\PanIO.sys type=kernel
sc.exe start PanIO.sys
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

| Filename | PanIO.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9a9dbf5107848c254381be67a4c1b1dd">9a9dbf5107848c254381be67a4c1b1dd</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/291b4a88ffd2ac1d6bf812ecaedc2d934dc503cb">291b4a88ffd2ac1d6bf812ecaedc2d934dc503cb</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f596e64f4c5d7c37a00493728d8756b243cfdc11e3372d6d6dfeffc13c9ab960">f596e64f4c5d7c37a00493728d8756b243cfdc11e3372d6d6dfeffc13c9ab960</a> |
| Signature | PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., GlobalSign CodeSigning CA - G2, GlobalSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/panio.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
