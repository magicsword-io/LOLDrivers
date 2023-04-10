+++

description = ""
title = "mhyprot.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mhyprot.sys ![:inline](/images/twitter_verified.png) 


### Description

mhyprot.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create mhyprot.sys binPath=C:\windows\temp\mhyprot.sys type=kernel
sc.exe start mhyprot.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Mhyprot.yar">https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Mhyprot.yar</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | mhyprot.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4b817d0e7714b9d43db43ae4a22a161e">4b817d0e7714b9d43db43ae4a22a161e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/0466e90bf0e83b776ca8716e01d35a8a2e5f96d3">0466e90bf0e83b776ca8716e01d35a8a2e5f96d3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6">509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6</a> |
| Signature | miHoYo Co.,Ltd., DigiCert Assured ID Code Signing CA-1, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
