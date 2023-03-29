+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "nscm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nscm.sys ![:inline](/images/twitter_verified.png) 


### Description

nscm.sys is a vulnerable driver. CVE-2013-3956.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create nscm.sys binPath=C:\windows\temp\nscm.sys type=kernel
sc.exe start nscm.sys
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

| Filename | nscm.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4a23e0f2c6f926a41b28d574cbc6ac30">4a23e0f2c6f926a41b28d574cbc6ac30</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/64e4ac8b9ea2f050933b7ec76a55dd04e97773b4">64e4ac8b9ea2f050933b7ec76a55dd04e97773b4</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/76660e91f1ff3cb89630df5af4fe09de6098d09baa66b1a130c89c3c5edd5b22">76660e91f1ff3cb89630df5af4fe09de6098d09baa66b1a130c89c3c5edd5b22</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nscm.sys.yml)

*last_updated:* 2023-03-29








{{< /column >}}
{{< /block >}}
