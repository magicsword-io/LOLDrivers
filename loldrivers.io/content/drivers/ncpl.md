+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "ncpl.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ncpl.sys ![:inline](/images/twitter_verified.png) 


### Description

ncpl.sys is a vulnerable driver. CVE-2013-3956.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ncpl.sys binPath=C:\windows\temp\ncpl.sys type=kernel
sc.exe start ncpl.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | ncpl.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a26e600652c33dd054731b4693bf5b01">a26e600652c33dd054731b4693bf5b01</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bbc1e5fd826961d93b76abd161314cb3592c4436">bbc1e5fd826961d93b76abd161314cb3592c4436</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6c7120e40fc850e4715058b233f5ad4527d1084a909114fd6a36b7b7573c4a44">6c7120e40fc850e4715058b233f5ad4527d1084a909114fd6a36b7b7573c4a44</a> |
| Signature | Novell, Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ncpl.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
