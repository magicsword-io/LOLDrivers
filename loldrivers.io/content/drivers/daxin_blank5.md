+++

description = ""
title = "daxin_blank5.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank5.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create daxin_blank5.sys binPath=C:\windows\temp\daxin_blank5.sys     type=kernel type=kernel &amp;&amp; sc.exe start daxin_blank5.sys
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

| Filename | daxin_blank5.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f242cffd9926c0ccf94af3bf16b6e527">f242cffd9926c0ccf94af3bf16b6e527</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/53f776d9a183c42b93960b270dddeafba74eb3fb">53f776d9a183c42b93960b270dddeafba74eb3fb</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9c2f3e9811f7d0c7463eaa1ee6f39c23f902f3797b80891590b43bbe0fdf0e51">9c2f3e9811f7d0c7463eaa1ee6f39c23f902f3797b80891590b43bbe0fdf0e51</a> |
| Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 1:29 AM 7/18/2008 || Company | n/a || Description | n/a || Product | n/a |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank5.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
