+++

description = ""
title = "fidpcidrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# fidpcidrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

fidpcidrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create fidpcidrv.sys binPath=C:\windows\temp\fidpcidrv.sys type=kernel &amp;&amp; sc.exe start fidpcidrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | fidpcidrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/08596732304351b311970ff96b21f451f23b1e25">08596732304351b311970ff96b21f451f23b1e25</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | fidpcidrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7838fb56fdab816bc1900a4720eea2fc9972ef7a">7838fb56fdab816bc1900a4720eea2fc9972ef7a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | fidpcidrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4789b910023a667bee70ff1f1a8f369cffb10fe8">4789b910023a667bee70ff1f1a8f369cffb10fe8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | fidpcidrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/eeff4ec4ebc12c6acd2c930dc2eaaf877cfec7ec">eeff4ec4ebc12c6acd2c930dc2eaaf877cfec7ec</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fidpcidrv.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
