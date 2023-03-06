+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "winio64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# winio64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


winio64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create winio64.sys binPath=C:\windows\temp\winio64.sys type=kernel
sc.exe start winio64.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf,hash:9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374">e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf,hash:9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winio64.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
