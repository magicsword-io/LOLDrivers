+++

description = "https://github.com/namazso/physmem_drivers"
title = "smep_namco.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# smep_namco.sys ![:inline](/images/twitter_verified.png) 



### Description


smep_namco.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create smep_namco.sys binPath=C:\windows\temp\smep_namco.sys type=kernel
sc.exe start smep_namco.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/7EC93F34EB323823EB199FBF8D06219086D517D0E8F4B9E348D7AFD41EC9FD5D">7EC93F34EB323823EB199FBF8D06219086D517D0E8F4B9E348D7AFD41EC9FD5D</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_namco.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
