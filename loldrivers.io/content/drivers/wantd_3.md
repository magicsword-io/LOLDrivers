+++

description = ""
title = "wantd_3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_3.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create wantd_3.sys binPath=C:\windows\temp\wantd_3.sys type=kernel
sc.exe start wantd_3.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>
<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | wantd_3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/fb7c61ef427f9b2fdff3574ee6b1819b">fb7c61ef427f9b2fdff3574ee6b1819b</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1f25f54e9b289f76604e81e98483309612c5a471">1f25f54e9b289f76604e81e98483309612c5a471</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1">81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1</a> |
| Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 7:52 AM 4/30/2014 || Company | Microsoft Corporation || Description | WAN Transport Driver || Product | Microsoft Windows Operating System |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_3.sys.yml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
