+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "rtkio.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkio.sys

#### Description

BSMEMx64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create rtkio binPath= C:\windows\temp\rtkio.sys type= kernel
sc.exe start rtkio.sys
```

#### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82">478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkio.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
