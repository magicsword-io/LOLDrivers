+++

description = ""
title = "winio64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# winio64.sys ![:inline](/images/twitter_verified.png) 


### Description

winio64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create winio64.sys binPath=C:\windows\temp\winio64.sys type=kernel
sc.exe start winio64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | winio64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/97221e16e7a99a00592ca278c49ffbfc">97221e16e7a99a00592ca278c49ffbfc</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/943593e880b4d340f2548548e6e673ef6f61eed3">943593e880b4d340f2548548e6e673ef6f61eed3</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf">e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf</a> |
| Signature | Exacq Technologies, Inc., StartCom Class 3 Primary Intermediate Object CA, StartCom Certification Authority   || Filename | winio64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/11fb599312cb1cf43ca5e879ed6fb71e">11fb599312cb1cf43ca5e879ed6fb71e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b4d014b5edd6e19ce0e8395a64faedf49688ecb5">b4d014b5edd6e19ce0e8395a64faedf49688ecb5</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374">9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winio64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
