+++

description = "https://github.com/namazso/physmem_drivers"
title = "dbutil_2_3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# dbutil_2_3.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


dbutil_2_3.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create dbutil_2_3.sys binPath=C:\windows\temp\dbutil_2_3.sys type=kernel
sc.exe start dbutil_2_3.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5">0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5</a></li>

<li><a href="https://www.virustotal.com/gui/file/c948ae14761095e4d76b55d9de86412258be7afd">c948ae14761095e4d76b55d9de86412258be7afd</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: Dell Inc.
- Company: 
- Description: dianhu
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutil_2_3.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
