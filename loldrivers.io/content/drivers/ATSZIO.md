+++

description = "https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"
title = "ATSZIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# ATSZIO.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


ATSZIO.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create ATSZIO.sys binPath=C:\windows\temp\ATSZIO.sys type=kernel
sc.exe start ATSZIO.sys
```

### Resources
<br>


<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>


<br>


### Binary Metadata
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

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
