+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "viragt.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# viragt.sys

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



<li><a href="https://www.virustotal.com/gui/file/e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53">e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/viragt.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
