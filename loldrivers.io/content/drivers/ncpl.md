+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "ncpl.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ncpl.sys

#### Description

ncpl.sys is a vulnerable driver. CVE-2013-3956.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create ncpl binPath= C:\windows\temp\ncpl.sys type= kernel
sc.exe start ncpl.sys
```

#### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/6c7120e40fc850e4715058b233f5ad4527d1084a909114fd6a36b7b7573c4a44">6c7120e40fc850e4715058b233f5ad4527d1084a909114fd6a36b7b7573c4a44</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ncpl.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
