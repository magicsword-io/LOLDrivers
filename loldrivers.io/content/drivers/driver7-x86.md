+++

description = "https://github.com/Chigusa0w0/AsusDriversPrivEscala"
title = "driver7-x86.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# driver7-x86.sys ![:inline](/images/twitter_verified.png) 


### Description

driver7-x86.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create driver7-x86.sys binPath=C:\windows\temp\driver7-x86.sys type=kernel
sc.exe start driver7-x86.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/Chigusa0w0/AsusDriversPrivEscala"> https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>
<br>

### Known Vulnerable Samples

| Filename | driver7-x86.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1f950cfd5ed8dd9de3de004f5416fe20">1f950cfd5ed8dd9de3de004f5416fe20</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/00b4e8b7644d1bf93f5ddb5740b444b445e81b02">00b4e8b7644d1bf93f5ddb5740b444b445e81b02</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/42851a01469ba97cdc38939b10cf9ea13237aa1f6c37b1ac84904c5a12a81fa0">42851a01469ba97cdc38939b10cf9ea13237aa1f6c37b1ac84904c5a12a81fa0</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x86.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
