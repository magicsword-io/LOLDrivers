+++

description = ""
title = "AsrDrv103.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv103.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv103.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv103.sys binPath=C:\windows\temp\AsrDrv103.sys type=kernel
sc.exe start AsrDrv103.sys
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

| Filename | AsrDrv103.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7c72a7e1d42b0790773efd8700e24952">7c72a7e1d42b0790773efd8700e24952</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/15d1a6a904c8409fb47a82aefa42f8c3c7d8c370">15d1a6a904c8409fb47a82aefa42f8c3c7d8c370</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d">2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d</a> |
| Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv103.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
