+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "vmdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vmdrv.sys

#### Description

CapCom.sys is a vulnerable driver that has been abused over the years.

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



<li><a href="https://www.virustotal.com/gui/file/32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351">32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vmdrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
