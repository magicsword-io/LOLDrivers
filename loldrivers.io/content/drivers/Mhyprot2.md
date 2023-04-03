+++

description = "https://github.com/namazso/physmem_drivers"
title = "Mhyprot2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Mhyprot2.sys ![:inline](/images/twitter_verified.png) 


### Description

Mhyprot2.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Mhyprot2.sys binPath=C:\windows\temp\Mhyprot2.sys type=kernel
sc.exe start Mhyprot2.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | Mhyprot2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4b817d0e7714b9d43db43ae4a22a161e">4b817d0e7714b9d43db43ae4a22a161e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/0466e90bf0e83b776ca8716e01d35a8a2e5f96d3">0466e90bf0e83b776ca8716e01d35a8a2e5f96d3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6">509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6</a> |
| Signature | miHoYo Co.,Ltd., DigiCert Assured ID Code Signing CA-1, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mhyprot2.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
