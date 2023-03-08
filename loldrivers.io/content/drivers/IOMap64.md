+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "IOMap64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# IOMap64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


IOMap64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create IOMap64.sys binPath=C:\windows\temp\IOMap64.sys type=kernel
sc.exe start IOMap64.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41">ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iomap64.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
