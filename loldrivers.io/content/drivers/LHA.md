+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "LHA.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# LHA.sys ![:inline](/images/twitter_verified.png) 



### Description


LHA.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create LHA.sys binPath=C:\windows\temp\LHA.sys type=kernel
sc.exe start LHA.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/e75714f8e0ff45605f6fc7689a1a89c7dcd34aab66c6131c63fefaca584539cf">e75714f8e0ff45605f6fc7689a1a89c7dcd34aab66c6131c63fefaca584539cf</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lha.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
