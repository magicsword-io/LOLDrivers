+++

description = ""
title = "BlackBoneDrv10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BlackBoneDrv10.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

BlackBoneDrv10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BlackBoneDrv10.sys binPath=C:\windows\temp\BlackBoneDrv10.sys type=kernel
sc.exe start BlackBoneDrv10.sys
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

| Filename | BlackBoneDrv10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f7393fb917aed182e4cbef25ce8af950">f7393fb917aed182e4cbef25ce8af950</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3ee2fd08137e9262d2e911158090e4a7c7427ea0">3ee2fd08137e9262d2e911158090e4a7c7427ea0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f51bdb0ad924178131c21e39a8ccd191e46b5512b0f2e1cc8486f63e84e5d960">f51bdb0ad924178131c21e39a8ccd191e46b5512b0f2e1cc8486f63e84e5d960</a> |
| Signature | Nanjing Zhixiao Information Technology Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/blackbonedrv10.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
