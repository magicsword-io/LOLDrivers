+++

description = ""
title = "AsrSmartConnectDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrSmartConnectDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrSmartConnectDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrSmartConnectDrv.sys binPath=C:\windows\temp\AsrSmartConnectDrv.sys type=kernel
sc.exe start AsrSmartConnectDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrSmartConnectDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/56a515173b211832e20fbc64e5a0447c">56a515173b211832e20fbc64e5a0447c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1d0df45ee3fa758f0470e055915004e6eae54c95">1d0df45ee3fa758f0470e055915004e6eae54c95</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/47f08f7d30d824a8f4bb8a98916401a37c0fd8502db308aba91fe3112b892dcc">47f08f7d30d824a8f4bb8a98916401a37c0fd8502db308aba91fe3112b892dcc</a> |
| Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | RW-Everything Read &amp; Write Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrsmartconnectdrv.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
