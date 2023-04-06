+++

description = ""
title = "speedfan.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# speedfan.sys ![:inline](/images/twitter_verified.png) 


### Description

speedfan.sys is a vulnerable driver. CVE-2007-5633.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create speedfan.sys binPath=C:\windows\temp\speedfan.sys type=kernel
sc.exe start speedfan.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | speedfan.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5f9785e7535f8f602cb294a54962c9e7">5f9785e7535f8f602cb294a54962c9e7</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bfe55cacc7c56c9f7bd75bdb4b352c0b745d071b">bfe55cacc7c56c9f7bd75bdb4b352c0b745d071b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c">22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c</a> |
| Signature | Sokno S.R.L., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/speedfan.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
