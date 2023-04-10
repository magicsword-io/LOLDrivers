+++

description = ""
title = "nvflash.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# nvflash.sys ![:inline](/images/twitter_verified.png) 


### Description

nvflash.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create nvflash.sys binPath=C:\windows\temp \n \n \n  vflash.sys type=kernel &amp;&amp; sc.exe start nvflash.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | nvflash.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/84fb76ee319073e77fb364bbbbff5461">84fb76ee319073e77fb364bbbbff5461</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a4b2c56c12799855162ca3b004b4b2078c6ecf77">a4b2c56c12799855162ca3b004b4b2078c6ecf77</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/afdd66562dea51001c3a9de300f91fc3eb965d6848dfce92ccb9b75853e02508">afdd66562dea51001c3a9de300f91fc3eb965d6848dfce92ccb9b75853e02508</a> |
| Signature | NVIDIA Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nvflash.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
