+++

description = "https://github.com/namazso/physmem_drivers"
title = "smep_capcom.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# smep_capcom.sys ![:inline](/images/twitter_verified.png) 


### Description

smep_capcom.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create smep_capcom.sys binPath=C:\windows\temp\smep_capcom.sys type=kernel
sc.exe start smep_capcom.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | smep_capcom.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f406c5536bcf9bacbeb7ce8a3c383bfa">f406c5536bcf9bacbeb7ce8a3c383bfa</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/21edff2937eb5cd6f6b0acb7ee5247681f624260">21edff2937eb5cd6f6b0acb7ee5247681f624260</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/db2a9247177e8cdd50fe9433d066b86ffd2a84301aa6b2eb60f361cfff077004">db2a9247177e8cdd50fe9433d066b86ffd2a84301aa6b2eb60f361cfff077004</a> |
| Publisher |  |
| Signature | CAPCOM Co.,Ltd., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_capcom.sys.yml)

*last_updated:* 2023-03-30








{{< /column >}}
{{< /block >}}
