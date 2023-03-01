+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "CorsairLLAccess64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# CorsairLLAccess64.sys

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



<li><a href="https://www.virustotal.com/gui/file/000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b">000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/corsairllaccess64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
