+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "libnicm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# libnicm.sys ![:inline](/images/twitter_verified.png) 


### Description

libnicm.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create libnicm.sys binPath=C:\windows\temp\libnicm.sys type=kernel
sc.exe start libnicm.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | libnicm.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c1fce7aac4e9dd7a730997e2979fa1e2">c1fce7aac4e9dd7a730997e2979fa1e2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/25d812a5ece19ea375178ef9d60415841087726e">25d812a5ece19ea375178ef9d60415841087726e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/95d50c69cdbf10c9c9d61e64fe864ac91e6f6caa637d128eb20e1d3510e776d3">95d50c69cdbf10c9c9d61e64fe864ac91e6f6caa637d128eb20e1d3510e776d3</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/libnicm.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
