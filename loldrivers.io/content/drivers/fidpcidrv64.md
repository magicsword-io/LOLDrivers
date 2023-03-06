+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "fidpcidrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# fidpcidrv64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


fidpcidrv64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create fidpcidrv64.sys binPath=C:\windows\temp\fidpcidrv64.sys type=kernel
sc.exe start fidpcidrv64.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46">3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fidpcidrv64.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
