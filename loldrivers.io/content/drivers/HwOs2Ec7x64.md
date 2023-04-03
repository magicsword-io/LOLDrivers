+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "HwOs2Ec7x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwOs2Ec7x64.sys ![:inline](/images/twitter_verified.png) 


### Description

HwOs2Ec7x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create HwOs2Ec7x64.sys binPath=C:\windows\temp\HwOs2Ec7x64.sys type=kernel
sc.exe start HwOs2Ec7x64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | HwOs2Ec7x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/bae1f127c4ff21d8fe45e2bbfc59c180">bae1f127c4ff21d8fe45e2bbfc59c180</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/26c4a7b392d7e7bd7f0a2a758534e45c0d9a56ab">26c4a7b392d7e7bd7f0a2a758534e45c0d9a56ab</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de">b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de</a> |
| Publisher |  |
| Signature | Huawei Technologies Co.,Ltd., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwos2ec7x64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
