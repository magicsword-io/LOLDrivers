+++

description = ""
title = "AsrDrv106.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv106.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv106.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv106.sys binPath=C:\windows\temp\AsrDrv106.sys type=kernel
sc.exe start AsrDrv106.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrDrv106.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/12908c285b9d68ee1f39186110df0f1e">12908c285b9d68ee1f39186110df0f1e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b0032b8d8e6f4bd19a31619ce38d8e010f29a816">b0032b8d8e6f4bd19a31619ce38d8e010f29a816</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838">3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838</a> |
| Signature | ASROCK INC., GlobalSign GCC R45 EV CodeSigning CA 2020, GlobalSign Code Signing Root R45, GlobalSign, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv106.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
