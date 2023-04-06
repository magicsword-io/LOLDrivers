+++

description = ""
title = "mydrivers.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mydrivers.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

mydrivers.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create mydrivers.sys binPath=C:\windows\temp\mydrivers.sys type=kernel
sc.exe start mydrivers.sys
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

| Filename | mydrivers.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/507a649eb585d8d0447eab0532ef0c73">507a649eb585d8d0447eab0532ef0c73</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7859e75580570e23a1ef7208b9a76f81738043d5">7859e75580570e23a1ef7208b9a76f81738043d5</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/08eb2d2aa25c5f0af4e72a7e0126735536f6c2c05e9c7437282171afe5e322c6">08eb2d2aa25c5f0af4e72a7e0126735536f6c2c05e9c7437282171afe5e322c6</a> |
| Signature | Beijing Kingsoft Security software Co.,Ltd, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mydrivers.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
