+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "d.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# d.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

d.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create d.sys binPath=C:\windows\temp\d.sys type=kernel
sc.exe start d.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | d.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a60c9173563b940203cf4ad38ccf2082">a60c9173563b940203cf4ad38ccf2082</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a3636986cdcd1d1cb8ab540f3d5c29dcc90bb8f0">a3636986cdcd1d1cb8ab540f3d5c29dcc90bb8f0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c1c4310e5d467d24e864177bdbfc57cb5d29aac697481bfa9c11ddbeebfd4cc8">c1c4310e5d467d24e864177bdbfc57cb5d29aac697481bfa9c11ddbeebfd4cc8</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/d.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
