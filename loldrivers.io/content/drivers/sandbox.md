+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "sandbox.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# sandbox.sys

#### Description

sandbox.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create sandbox binPath= C:\windows\temp\sandbox.sys type= kernel
sc.exe start sandbox.sys
```

#### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>


<br>


#### Binary Metadata
<br>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sandbox.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
