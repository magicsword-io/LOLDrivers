+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "procexp.Sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# procexp.Sys ![:inline](/images/twitter_verified.png) 


### Description

procexp.Sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create procexp.Sys binPath=C:\windows\temp\procexp.Sys type=kernel
sc.exe start procexp.Sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | procexp.Sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/97e3a44ec4ae58c8cc38eefc613e950e">97e3a44ec4ae58c8cc38eefc613e950e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bc47e15537fa7c32dfefd23168d7e1741f8477ed">bc47e15537fa7c32dfefd23168d7e1741f8477ed</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c">440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/procexp.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
