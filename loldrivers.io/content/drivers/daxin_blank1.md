+++

description = ""
title = "daxin_blank1.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank1.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create daxin_blank1.sys binPath=C:\windows\temp\daxin_blank1.sys type=kernel
sc.exe start daxin_blank1.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>
<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>
<br>

### Known Vulnerable Samples

| Filename | daxin_blank1.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a6e9d6505f6d2326a8a9214667c61c67">a6e9d6505f6d2326a8a9214667c61c67</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cb3f30809b05cf02bc29d4a7796fb0650271e542">cb3f30809b05cf02bc29d4a7796fb0650271e542</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae">5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae</a> |
| Publisher | Fuqing Yuntan Network Tech Co.,Ltd. || Signature | A,  , c, e, r, t, i, f, i, c, a, t, e,  , w, a, s,  , e, x, p, l, i, c, i, t, l, y,  , r, e, v, o, k, e, d,  , b, y,  , i, t, s,  , i, s, s, u, e, r, .   || Date | 4:05 AM 2/6/2021 || Company | n/a || Description | n/a || Product | n/a |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank1.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
