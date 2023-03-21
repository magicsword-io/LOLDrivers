+++

description = ""
title = "PcieCubed.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PcieCubed.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create PcieCubed.sys binPath=C:\windows\temp\PcieCubed.sys type=kernel
sc.exe start PcieCubed.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<br>

### Known Vulnerable Samples

| Filename | PcieCubed.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/22949977ce5cd96ba674b403a9c81285">22949977ce5cd96ba674b403a9c81285</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/"></a> |
| Publisher |  |
| Signature |  |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/pciecubed.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
