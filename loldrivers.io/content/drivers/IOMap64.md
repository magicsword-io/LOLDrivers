+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "IOMap64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# IOMap64.sys ![:inline](/images/twitter_verified.png) 


### Description

IOMap64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create IOMap64.sys binPath=C:\windows\temp\IOMap64.sys type=kernel
sc.exe start IOMap64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | IOMap64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a01c412699b6f21645b2885c2bae4454">a01c412699b6f21645b2885c2bae4454</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2fc6845047abcf2a918fce89ab99e4955d08e72c">2fc6845047abcf2a918fce89ab99e4955d08e72c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41">ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41</a> |
| Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iomap64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
