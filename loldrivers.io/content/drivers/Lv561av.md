+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "Lv561av.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Lv561av.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

Lv561av.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Lv561av.sys binPath=C:\windows\temp\Lv561av.sys type=kernel
sc.exe start Lv561av.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | Lv561av.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b47dee29b5e6e1939567a926c7a3e6a4">b47dee29b5e6e1939567a926c7a3e6a4</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/351cbd352b3ec0d5f4f58c84af732a0bf41b4463">351cbd352b3ec0d5f4f58c84af732a0bf41b4463</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e86cb77de7b6a8025f9a546f6c45d135f471e664963cf70b381bee2dfd0fdef4">e86cb77de7b6a8025f9a546f6c45d135f471e664963cf70b381bee2dfd0fdef4</a> |
| Publisher |  |
| Signature | Logitech Inc, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lv561av.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
