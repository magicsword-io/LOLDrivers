+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "BSMI.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMI.sys

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



<li><a href="https://www.virustotal.com/gui/file/59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347">59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmi.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
