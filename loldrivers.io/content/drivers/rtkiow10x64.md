+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "rtkiow10x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkiow10x64.sys ![:inline](/images/twitter_verified.png) 


### Description

rtkiow10x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create rtkiow10x64.sys binPath=C:\windows\temp\rtkiow10x64.sys type=kernel
sc.exe start rtkiow10x64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | rtkiow10x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b5ada7fd226d20ec6634fc24768f9e22">b5ada7fd226d20ec6634fc24768f9e22</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/947db58d6f36a8df9fa2a1057f3a7f653ccbc42e">947db58d6f36a8df9fa2a1057f3a7f653ccbc42e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/32e1a8513eee746d17eb5402fb9d8ff9507fb6e1238e7ff06f7a5c50ff3df993">32e1a8513eee746d17eb5402fb9d8ff9507fb6e1238e7ff06f7a5c50ff3df993</a> |
| Signature | Realtek Semiconductor Corp., DigiCert EV Code Signing CA, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkiow10x64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
