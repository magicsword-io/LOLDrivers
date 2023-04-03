+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "nvflsh64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nvflsh64.sys ![:inline](/images/twitter_verified.png) 


### Description

nvflsh64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create nvflsh64.sys binPath=C:\windows\temp\nvflsh64.sys type=kernel
sc.exe start nvflsh64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | nvflsh64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d3e40644a91327da2b1a7241606fe559">d3e40644a91327da2b1a7241606fe559</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7667b72471689151e176baeba4e1cd9cd006a09a">7667b72471689151e176baeba4e1cd9cd006a09a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3">a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3</a> |
| Publisher |  |
| Signature | NVIDIA Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nvflsh64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
