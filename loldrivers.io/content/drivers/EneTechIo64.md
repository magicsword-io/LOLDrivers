+++

description = ""
title = "EneTechIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# EneTechIo64.sys ![:inline](/images/twitter_verified.png) 


### Description

EneTechIo64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create EneTechIo64.sys binPath=C:\windows\temp\EneTechIo64.sys type=kernel
sc.exe start EneTechIo64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<li><a href="https://github.com/hfiref0x/KDU/releases/tag/v1.2.0">https://github.com/hfiref0x/KDU/releases/tag/v1.2.0</a></li>
<li><a href="https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c">https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Filename | EneTechIo64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d6e9f6c67d9b3d790d592557a7d57c3c">d6e9f6c67d9b3d790d592557a7d57c3c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a87d6eac2d70a3fbc04e59412326b28001c179de">a87d6eac2d70a3fbc04e59412326b28001c179de</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/06bda5a1594f7121acd2efe38ccb617fbc078bb9a70b665a5f5efd70e3013f50">06bda5a1594f7121acd2efe38ccb617fbc078bb9a70b665a5f5efd70e3013f50</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/enetechio64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
