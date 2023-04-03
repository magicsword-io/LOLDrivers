+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "sandra.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# sandra.sys ![:inline](/images/twitter_verified.png) 


### Description

sandra.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create sandra.sys binPath=C:\windows\temp\sandra.sys type=kernel
sc.exe start sandra.sys
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

| Filename | sandra.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9a237fa07ce3ed06ea924a9bed4a6b99">9a237fa07ce3ed06ea924a9bed4a6b99</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/82ba5513c33e056c3f54152c8555abf555f3e745">82ba5513c33e056c3f54152c8555abf555f3e745</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1aaf4c1e3cb6774857e2eef27c17e68dc1ae577112e4769665f516c2e8c4e27b">1aaf4c1e3cb6774857e2eef27c17e68dc1ae577112e4769665f516c2e8c4e27b</a> |
| Publisher |  |
| Signature | SiSoftware Ltd, GeoTrust TrustCenter CodeSigning CA I, GeoTrust   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sandra.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
