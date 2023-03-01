+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "mhyprot.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mhyprot.sys

#### Description

mhyprot.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create mhyprot binPath= C:\windows\temp\mhyprot.sys type= kernel
sc.exe start mhyprot.sys
```

#### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>

<li><a href="https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Mhyprot.yar">https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Mhyprot.yar</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6">509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
