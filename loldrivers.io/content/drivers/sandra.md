+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "sandra.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# sandra.sys

#### Description

sandra.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create sandra binPath= C:\windows\temp\sandra.sys type= kernel
sc.exe start sandra.sys
```

#### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/1aaf4c1e3cb6774857e2eef27c17e68dc1ae577112e4769665f516c2e8c4e27b">1aaf4c1e3cb6774857e2eef27c17e68dc1ae577112e4769665f516c2e8c4e27b</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sandra.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
