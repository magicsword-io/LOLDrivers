+++

description = ""
title = "driver7-x86-withoutdbg.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# driver7-x86-withoutdbg.sys ![:inline](/images/twitter_verified.png) 


### Description

driver7-x86-withoutdbg.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create driver7-x86-withoutdbg.sys binPath=C:\windows\temp\driver7-x86-withoutdbg.sys type=kernel
sc.exe start driver7-x86-withoutdbg.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/Chigusa0w0/AsusDriversPrivEscala"> https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>
<li><a href="https://github.com/Chigusa0w0/AsusDriversPrivEscala">https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>
<br>

### Known Vulnerable Samples

| Filename | driver7-x86-withoutdbg.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4f191abc652d8f7442ca2636725e1ed6">4f191abc652d8f7442ca2636725e1ed6</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4243dbbf6e5719d723f24d0f862afd0fcb40bc35">4243dbbf6e5719d723f24d0f862afd0fcb40bc35</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/927c2a580d51a598177fa54c65e9d2610f5f212f1b6cb2fbf2740b64368f010a">927c2a580d51a598177fa54c65e9d2610f5f212f1b6cb2fbf2740b64368f010a</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x86-withoutdbg.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
