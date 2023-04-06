+++

description = ""
title = "amp.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# amp.sys ![:inline](/images/twitter_verified.png) 


### Description

amp.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create amp.sys binPath=C:\windows\temp\amp.sys type=kernel
sc.exe start amp.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<li><a href="https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c">https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Filename | amp.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c533d6d64b474ffc3169a0e0fc0a701a">c533d6d64b474ffc3169a0e0fc0a701a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3f223581409492172a1e875f130f3485b90fbe5f">3f223581409492172a1e875f130f3485b90fbe5f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6">cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amp.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
