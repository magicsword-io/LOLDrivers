+++

description = ""
title = "otipcibus.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# otipcibus.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

otipcibus.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create otipcibus.sys binPath=C:\windows\temp\otipcibus.sys type=kernel
sc.exe start otipcibus.sys
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

| Filename | otipcibus.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d5a642329cce4df94b8dc1ba9660ae34">d5a642329cce4df94b8dc1ba9660ae34</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ccdd3a1ebe9a1c8f8a72af20a05a10f11da1d308">ccdd3a1ebe9a1c8f8a72af20a05a10f11da1d308</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4e3eb5b9bce2fd9f6878ae36288211f0997f6149aa8c290ed91228ba4cdfae80">4e3eb5b9bce2fd9f6878ae36288211f0997f6149aa8c290ed91228ba4cdfae80</a> |
| Signature | Ours Technology Inc., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/otipcibus.sys.yml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
