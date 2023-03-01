+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "procexp.Sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# procexp.Sys

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



<li><a href="https://www.virustotal.com/gui/file/440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c">440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/procexp.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
