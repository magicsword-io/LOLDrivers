+++

description = ""
title = "BS_HWMIO64_W10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_HWMIO64_W10.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_HWMIO64_W10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BS_HWMIO64_W10.sys binPath=C:\windows\temp\BS_HWMIO64_W10.sys type=kernel
sc.exe start BS_HWMIO64_W10.sys
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

| Filename | BS_HWMIO64_W10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d2588631d8aae2a3e54410eaf54f0679">d2588631d8aae2a3e54410eaf54f0679</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cb3de54667548a5c9abf5d8fa47db4097fcee9f1">cb3de54667548a5c9abf5d8fa47db4097fcee9f1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8">1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_hwmio64_w10.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
