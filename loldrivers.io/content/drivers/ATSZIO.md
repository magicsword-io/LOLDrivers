+++

description = "https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"
title = "ATSZIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ATSZIO.sys

#### Description

CapCom.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create ATSZIO binPath= C:\windows\temp\ATSZIO.sys type= kernel
sc.exe start ATSZIO.sys
```

#### Resources
<br>


<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece">01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atszio.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
