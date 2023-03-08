+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "TmComm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# TmComm.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


TmComm.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create TmComm.sys binPath=C:\windows\temp\TmComm.sys type=kernel
sc.exe start TmComm.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/cc687fe3741bbde1dd142eac0ef59fd1d4457daee43cdde23bb162ef28d04e64">cc687fe3741bbde1dd142eac0ef59fd1d4457daee43cdde23bb162ef28d04e64</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: 
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/tmcomm.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
