+++

description = ""
title = "HwOs2Ec10x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwOs2Ec10x64.sys ![:inline](/images/twitter_verified.png) 


### Description

HwOs2Ec10x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create HwOs2Ec10x64.sys binPath=C:\windows\temp\HwOs2Ec10x64.sys type=kernel
sc.exe start HwOs2Ec10x64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | HwOs2Ec10x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/37086ae5244442ba552803984a11d6cb">37086ae5244442ba552803984a11d6cb</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/dc0e97adb756c0f30b41840a59b85218cbdd198f">dc0e97adb756c0f30b41840a59b85218cbdd198f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc">bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc</a> |
| Signature | Huawei Technologies Co., Ltd., Symantec Class 3 Extended Validation Code Signing CA - G2, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwos2ec10x64.sys.yml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
