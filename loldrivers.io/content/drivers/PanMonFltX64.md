+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "PanMonFltX64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PanMonFltX64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

PanMonFltX64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create PanMonFltX64.sys binPath=C:\windows\temp\PanMonFltX64.sys type=kernel
sc.exe start PanMonFltX64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | PanMonFltX64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0067c788e1cb174f008c325ebde56c22">0067c788e1cb174f008c325ebde56c22</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/12d38abbc5391369a4c14f3431715b5b76ac5a2a">12d38abbc5391369a4c14f3431715b5b76ac5a2a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/06508aacb4ed0a1398a2b0da5fa2dbf7da435b56da76fd83c759a50a51c75caf">06508aacb4ed0a1398a2b0da5fa2dbf7da435b56da76fd83c759a50a51c75caf</a> |
| Signature | PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., GlobalSign CodeSigning CA - G2, GlobalSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/panmonfltx64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
