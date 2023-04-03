+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "CorsairLLAccess64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# CorsairLLAccess64.sys ![:inline](/images/twitter_verified.png) 


### Description

CorsairLLAccess64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create CorsairLLAccess64.sys binPath=C:\windows\temp\CorsairLLAccess64.sys type=kernel
sc.exe start CorsairLLAccess64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | CorsairLLAccess64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/803a371a78d528a44ef8777f67443b16">803a371a78d528a44ef8777f67443b16</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5fb9421be8a8b08ec395d05e00fd45eb753b593a">5fb9421be8a8b08ec395d05e00fd45eb753b593a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b">000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/corsairllaccess64.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
