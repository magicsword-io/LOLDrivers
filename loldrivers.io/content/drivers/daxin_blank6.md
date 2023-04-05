+++

description = ""
title = "daxin_blank6.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank6.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create daxin_blank6.sys binPath=C:\windows\temp\daxin_blank6.sys type=kernel
sc.exe start daxin_blank6.sys
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

| Filename | daxin_blank6.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/0ae30291c6cbfa7be39320badd6e8de0">0ae30291c6cbfa7be39320badd6e8de0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c257aa4094539719a3c7b7950598ef872dbf9518">c257aa4094539719a3c7b7950598ef872dbf9518</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e6a7b0bc01a627a7d0ffb07faddb3a4dd96b6f5208ac26107bdaeb3ab1ec8217">e6a7b0bc01a627a7d0ffb07faddb3a4dd96b6f5208ac26107bdaeb3ab1ec8217</a> |
| Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 2:44 AM 3/26/2009 || Company | n/a || Description | n/a || Product | n/a |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank6.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
