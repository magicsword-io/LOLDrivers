+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "LgDCatcher.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LgDCatcher.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

LgDCatcher.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create LgDCatcher.sys binPath=C:\windows\temp\LgDCatcher.sys type=kernel
sc.exe start LgDCatcher.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | LgDCatcher.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ed6348707f177629739df73b97ba1b6e">ed6348707f177629739df73b97ba1b6e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/806832983bb8cb1e26001e60ea3b7c3ade4d3471">806832983bb8cb1e26001e60ea3b7c3ade4d3471</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/58c071cfe72e9ee867bba85cbd0abe72eb223d27978d6f0650d0103553839b59">58c071cfe72e9ee867bba85cbd0abe72eb223d27978d6f0650d0103553839b59</a> |
| Signature | 雷神（武汉）信息技术有限公司, DigiCert SHA2 Assured ID Code Signing CA, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lgdcatcher.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
