+++

description = ""
title = "mtcBSv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mtcBSv64.sys ![:inline](/images/twitter_verified.png) 


### Description

mtcBSv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create mtcBSv64.sys binPath=C:\windows\temp\mtcBSv64.sys type=kernel &amp;&amp; sc.exe start mtcBSv64.sys
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

| Filename | mtcBSv64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9dfd73dadb2f1c7e9c9d2542981aaa63">9dfd73dadb2f1c7e9c9d2542981aaa63</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/29a190727140f40cea9514a6420f5a195e36386b">29a190727140f40cea9514a6420f5a195e36386b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c9cf1d627078f63a36bbde364cd0d5f2be1714124d186c06db5bcdf549a109f8">c9cf1d627078f63a36bbde364cd0d5f2be1714124d186c06db5bcdf549a109f8</a> |
| Signature | Mitac Technology Corporation, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mtcbsv64.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
