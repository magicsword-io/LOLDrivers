+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "rtkiow8x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkiow8x64.sys ![:inline](/images/twitter_verified.png) 


### Description

rtkiow8x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create rtkiow8x64.sys binPath=C:\windows\temp\rtkiow8x64.sys type=kernel
sc.exe start rtkiow8x64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | rtkiow8x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b8b6686324f7aa77f570bc019ec214e6">b8b6686324f7aa77f570bc019ec214e6</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6a3d3b9ab3d201cd6b0316a7f9c3fb4d34d0f403">6a3d3b9ab3d201cd6b0316a7f9c3fb4d34d0f403</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d">082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d</a> |
| Signature | Realtek Semiconductor Corp., DigiCert EV Code Signing CA, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkiow8x64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
