+++

description = ""
title = "wantd.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create wantd.sys binPath=C:\windows\temp\wantd.sys type=kernel
sc.exe start wantd.sys
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

| Filename | wantd.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b0770094c3c64250167b55e4db850c04">b0770094c3c64250167b55e4db850c04</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6abbc3003c7aa69ce79cbbcd2e3210b07f21d202">6abbc3003c7aa69ce79cbbcd2e3210b07f21d202</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4">06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4</a> |
| Publisher | Anhua Xinda (Beijing) Technology Co., Ltd. || Signature | A,  , r, e, q, u, i, r, e, d,  , c, e, r, t, i, f, i, c, a, t, e,  , i, s,  , n, o, t,  , w, i, t, h, i, n,  , i, t, s,  , v, a, l, i, d, i, t, y,  , p, e, r, i, o, d,  , w, h, e, n,  , v, e, r, i, f, y, i, n, g,  , a, g, a, i, n, s, t,  , t, h, e,  , c, u, r, r, e, n, t,  , s, y, s, t, e, m,  , c, l, o, c, k,  , o, r,  , t, h, e,  , t, i, m, e, s, t, a, m, p,  , i, n,  , t, h, e,  , s, i, g, n, e, d,  , f, i, l, e, .   || Date | 11:59 PM 11/27/2013 || Company | Microsoft Corporation || Description | WAN Transport Driver || Product | Microsoft Windows Operating System |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
