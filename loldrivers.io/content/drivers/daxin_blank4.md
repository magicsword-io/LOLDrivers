+++

description = ""
title = "daxin_blank4.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank4.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create daxin_blank4.sys binPath=C:\windows\temp\daxin_blank4.sys type=kernel
sc.exe start daxin_blank4.sys
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

| Filename | daxin_blank4.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/491aec2249ad8e2020f9f9b559ab68a8">491aec2249ad8e2020f9f9b559ab68a8</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/8692274681e8d10c26ddf2b993f31974b04f5bf0">8692274681e8d10c26ddf2b993f31974b04f5bf0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e">8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e</a> |
| Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 8:42 AM 4/20/2010 || Company | n/a || Description | n/a || Product | n/a |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank4.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
