+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "cpuz.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz.sys

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



<li><a href="https://www.virustotal.com/gui/file/8c95d28270a4a314299cf50f05dcbe63033b2a555195d2ad2f678e09e00393e6">8c95d28270a4a314299cf50f05dcbe63033b2a555195d2ad2f678e09e00393e6</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
