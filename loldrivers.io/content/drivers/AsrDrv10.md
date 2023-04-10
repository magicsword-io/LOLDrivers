+++

description = ""
title = "AsrDrv10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv10.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv10.sys binPath=C:\windows\temp\AsrDrv10.sys type=kernel
sc.exe start AsrDrv10.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrDrv10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9b91a44a488e4d539f2e55476b216024">9b91a44a488e4d539f2e55476b216024</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/72966ca845759d239d09da0de7eebe3abe86fee3">72966ca845759d239d09da0de7eebe3abe86fee3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/ece0a900ea089e730741499614c0917432246ceb5e11599ee3a1bb679e24fd2c">ece0a900ea089e730741499614c0917432246ceb5e11599ee3a1bb679e24fd2c</a> |
| Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | ASRock IO Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv10.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
