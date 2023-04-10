+++

description = ""
title = "wantd_2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_2.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create wantd_2.sys binPath=C:\windows\temp\wantd_2.sys type=kernel
sc.exe start wantd_2.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>
<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | wantd_2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/8636fe3724f2bcba9399daffd6ef3c7e">8636fe3724f2bcba9399daffd6ef3c7e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3b6b35bca1b05fafbfc883a844df6d52af44ccdc">3b6b35bca1b05fafbfc883a844df6d52af44ccdc</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f">6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f</a> |
| Publisher | Anhua Xinda (Beijing) Technology Co., Ltd. || Signature | S, i, g, n, e, d   || Date | 7:52 AM 4/30/2014 || Company | Microsoft Corporation || Description | WAN Transport Driver || Product | Microsoft Windows Operating System |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_2.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
