+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "viraglt64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# viraglt64.sys ![:inline](/images/twitter_verified.png) 


### Description

viraglt64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create viraglt64.sys binPath=C:\windows\temp\viraglt64.sys type=kernel
sc.exe start viraglt64.sys
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

| Filename | viraglt64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/43830326cd5fae66f5508e27cbec39a0">43830326cd5fae66f5508e27cbec39a0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/05c0c49e8bcf11b883d41441ce87a2ee7a3aba1d">05c0c49e8bcf11b883d41441ce87a2ee7a3aba1d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495">58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495</a> |
| Publisher |  |
| Signature | TG Soft S.a.s. Di Tonello Gianfranco e C., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/viraglt64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
