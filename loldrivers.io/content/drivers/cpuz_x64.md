+++

description = "https://github.com/namazso/physmem_drivers"
title = "cpuz_x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz_x64.sys ![:inline](/images/twitter_verified.png) 


### Description

cpuz_x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create cpuz_x64.sys binPath=C:\windows\temp\cpuz_x64.sys type=kernel
sc.exe start cpuz_x64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | cpuz_x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7d46d0ddaf8c7e1776a70c220bf47524">7d46d0ddaf8c7e1776a70c220bf47524</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d2e6fc9259420f0c9b6b1769be3b1f63eb36dc57">d2e6fc9259420f0c9b6b1769be3b1f63eb36dc57</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3871e16758a1778907667f78589359734f7f62f9dc953ec558946dcdbe6951e3">3871e16758a1778907667f78589359734f7f62f9dc953ec558946dcdbe6951e3</a> |
| Publisher | CPUID || Signature | CPUID, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Description | CPUID Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cpuz_x64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
