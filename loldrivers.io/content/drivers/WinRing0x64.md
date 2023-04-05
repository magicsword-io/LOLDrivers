+++

description = ""
title = "WinRing0x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinRing0x64.sys ![:inline](/images/twitter_verified.png) 


### Description

WinRing0x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WinRing0x64.sys binPath=C:\windows\temp\WinRing0x64.sys type=kernel
sc.exe start WinRing0x64.sys
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

| Filename | WinRing0x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0c0195c48b6b8582fa6f6373032118da">0c0195c48b6b8582fa6f6373032118da</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d25340ae8e92a6d29f599fef426a2bc1b5217299">d25340ae8e92a6d29f599fef426a2bc1b5217299</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5">11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5</a> |
| Signature | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winring0x64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
