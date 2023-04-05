+++

description = ""
title = "DirectIo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# DirectIo.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

DirectIo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create DirectIo.sys binPath=C:\windows\temp\DirectIo.sys type=kernel
sc.exe start DirectIo.sys
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

| Filename | DirectIo.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a785b3bc4309d2eb111911c1b55e793f">a785b3bc4309d2eb111911c1b55e793f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/19f3343bfad0ef3595f41d60272d21746c92ffca">19f3343bfad0ef3595f41d60272d21746c92ffca</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4422851a0a102f654e95d3b79c357ae3af1b096d7d1576663c027cfbc04abaf9">4422851a0a102f654e95d3b79c357ae3af1b096d7d1576663c027cfbc04abaf9</a> |
| Signature | PassMark Software Pty Ltd, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/directio.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
