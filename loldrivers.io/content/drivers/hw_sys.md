+++

description = ""
title = "hw_sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# hw_sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

hw_sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create hw_sys binPath=C:\windows\temp\hw_sys type=kernel
sc.exe start hw_sys
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

| Filename | hw_sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/3247014ba35d406475311a2eab0c4657">3247014ba35d406475311a2eab0c4657</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/74e4e3006b644392f5fcea4a9bae1d9d84714b57">74e4e3006b644392f5fcea4a9bae1d9d84714b57</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4880f40f2e557cff38100620b9aa1a3a753cb693af16cd3d95841583edcb57a8">4880f40f2e557cff38100620b9aa1a3a753cb693af16cd3d95841583edcb57a8</a> |
| Signature | Marvin Test Solutions, Inc., GlobalSign Extended Validation CodeSigning CA - SHA256 - G3, GlobalSign, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hw_sys.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
