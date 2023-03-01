+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "TmComm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# TmComm.sys

#### Description

BSMEMx64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrDrv103 binPath= C:\windows\temp\AsrDrv103.sys type= kernel
sc.exe start AsrDrv103.sys
```

#### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


#### Binary Metadata
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

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
