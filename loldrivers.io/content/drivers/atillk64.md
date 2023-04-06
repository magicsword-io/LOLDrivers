+++

description = ""
title = "atillk64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# atillk64.sys ![:inline](/images/twitter_verified.png) 


### Description

atillk64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create atillk64.sys binPath=C:\windows\temp\atillk64.sys type=kernel
sc.exe start atillk64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | atillk64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/62f02339fe267dc7438f603bfb5431a1">62f02339fe267dc7438f603bfb5431a1</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c52cef5b9e1d4a78431b7af56a6fdb6aa1bcad65">c52cef5b9e1d4a78431b7af56a6fdb6aa1bcad65</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5c04c274a708c9a7d993e33be3ea9e6119dc29527a767410dbaf93996f87369a">5c04c274a708c9a7d993e33be3ea9e6119dc29527a767410dbaf93996f87369a</a> |
| Publisher | &#34;ATI Technologies, Inc&#34; || Signature | ATI Technologies, Inc, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Description | ATI Diagnostics Hardware Abstraction Sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/atillk64.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
