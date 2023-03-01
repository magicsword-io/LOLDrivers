+++

description = "https://github.com/namazso/physmem_drivers"
title = "atillk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# atillk64.sys

#### Description

atillk64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create atillk64 binPath= C:\windows\temp\atillk64.sys type= kernel
sc.exe start atillk64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/5C04C274A708C9A7D993E33BE3EA9E6119DC29527A767410DBAF93996F87369A">5C04C274A708C9A7D993E33BE3EA9E6119DC29527A767410DBAF93996F87369A</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: &#34;ATI Technologies, Inc&#34;
- Company: 
- Description: ATI Diagnostics Hardware Abstraction Sys
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atillk64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
