+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "nicm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nicm.sys ![:inline](/images/twitter_verified.png) 


### Description

nicm.sys is a vulnerable driver. CVE-2013-3956.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create nicm.sys binPath=C:\windows\temp\nicm.sys type=kernel
sc.exe start nicm.sys
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

| Filename | nicm.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/22823fed979903f8dfe3b5d28537eb47">22823fed979903f8dfe3b5d28537eb47</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d098600152e5ee6a8238d414d2a77a34da8afaaa">d098600152e5ee6a8238d414d2a77a34da8afaaa</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e6056443537d4d2314dabca1b9168f1eaaf17a14eb41f6f5741b6b82b3119790">e6056443537d4d2314dabca1b9168f1eaaf17a14eb41f6f5741b6b82b3119790</a> |
| Publisher |  |
| Signature | Novell, Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nicm.sys.yml)

*last_updated:* 2023-03-29








{{< /column >}}
{{< /block >}}
