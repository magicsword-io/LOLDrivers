+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "vmdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vmdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

vmdrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create vmdrv.sys binPath=C:\windows\temp\vmdrv.sys type=kernel
sc.exe start vmdrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | vmdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351">32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vmdrv.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
