+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "DBUtilDrv2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# DBUtilDrv2.sys

#### Description

DBUtilDrv2.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create DBUtilDrv2 binPath= C:\windows\temp\DBUtilDrv2.sys type= kernel
sc.exe start DBUtilDrv2.sys
```

#### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/90a76945fd2fa45fab2b7bcfdaf6563595f94891">90a76945fd2fa45fab2b7bcfdaf6563595f94891</a></li>

<li><a href="https://www.virustotal.com/gui/file/b03b1996a40bfea72e4584b82f6b845c503a9748">b03b1996a40bfea72e4584b82f6b845c503a9748</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutildrv2.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
