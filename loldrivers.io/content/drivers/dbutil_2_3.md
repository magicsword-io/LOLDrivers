+++

description = ""
title = "dbutil_2_3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbutil_2_3.sys ![:inline](/images/twitter_verified.png) 


### Description

dbutil_2_3.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create dbutil_2_3.sys binPath=C:\windows\temp\dbutil_2_3.sys type=kernel &amp;&amp; sc.exe start dbutil_2_3.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | dbutil_2_3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c996d7971c49252c582171d9380360f2">c996d7971c49252c582171d9380360f2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c948ae14761095e4d76b55d9de86412258be7afd">c948ae14761095e4d76b55d9de86412258be7afd</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5">0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5</a> |
| Publisher | Dell Inc. || Signature | Dell Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Description | dianhu || Filename | dbutil_2_3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c996d7971c49252c582171d9380360f2">c996d7971c49252c582171d9380360f2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c948ae14761095e4d76b55d9de86412258be7afd">c948ae14761095e4d76b55d9de86412258be7afd</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5">0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5</a> |
| Publisher | Dell Inc. || Signature | Dell Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Description | dianhu |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutil_2_3.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
