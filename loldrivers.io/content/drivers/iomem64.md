+++

description = ""
title = "iomem64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# iomem64.sys ![:inline](/images/twitter_verified.png) 


### Description

iomem64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create iomem64.sys binPath=C:\windows\temp\iomem64.sys type=kernel
sc.exe start iomem64.sys
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

| Filename | iomem64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0898af0888d8f7a9544ef56e5e16354e">0898af0888d8f7a9544ef56e5e16354e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4b009e91bae8d27b160dc195f10c095f8a2441e1">4b009e91bae8d27b160dc195f10c095f8a2441e1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3d23bdbaf9905259d858df5bf991eb23d2dc9f4ecda7f9f77839691acef1b8c4">3d23bdbaf9905259d858df5bf991eb23d2dc9f4ecda7f9f77839691acef1b8c4</a> |
| Signature | DT RESEARCH, INC. TAIWAN BRANCH, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Filename | iomem64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f1e054333cc40f79cfa78e5fbf3b54c2">f1e054333cc40f79cfa78e5fbf3b54c2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6003184788cd3d2fc624ca801df291ccc4e225ee">6003184788cd3d2fc624ca801df291ccc4e225ee</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/dd4a1253d47de14ef83f1bc8b40816a86ccf90d1e624c5adf9203ae9d51d4097">dd4a1253d47de14ef83f1bc8b40816a86ccf90d1e624c5adf9203ae9d51d4097</a> |
| Signature | DT RESEARCH, INC. TAIWAN BRANCH, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iomem64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
