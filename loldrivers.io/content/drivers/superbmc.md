+++

description = ""
title = "superbmc.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# superbmc.sys ![:inline](/images/twitter_verified.png) 


### Description

superbmc.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create superbmc.sys binPath=C:\windows\temp\superbmc.sys type=kernel &amp;&amp; sc.exe start superbmc.sys
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

| Filename | superbmc.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/3473faea65fba5d4fbe54c0898a3c044">3473faea65fba5d4fbe54c0898a3c044</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/910cb12aa49e9f35ecc4907e8304adf0dcca8cf1">910cb12aa49e9f35ecc4907e8304adf0dcca8cf1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f8430bdc6fd01f42217d66d87a3ef6f66cb2700ebb39c4f25c8b851858cc4b35">f8430bdc6fd01f42217d66d87a3ef6f66cb2700ebb39c4f25c8b851858cc4b35</a> |
| Signature | Super Micro Computer, Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/superbmc.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
