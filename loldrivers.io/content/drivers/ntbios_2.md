+++

description = ""
title = "ntbios_2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ntbios_2.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ntbios_2.sys binPath=C:\windows\temp\ntbios_2.sys type=kernel
sc.exe start ntbios_2.sys
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

| Filename | ntbios_2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/50b39072d0ee9af5ef4824eca34be6e3">50b39072d0ee9af5ef4824eca34be6e3</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/064de88dbbea67c149e779aac05228e5405985c7">064de88dbbea67c149e779aac05228e5405985c7</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c">c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c</a> |
| Publisher | n/a || Signature | U, n, s, i, g, n, e, d   || Date | 3:04 AM 5/18/2009 || Company | Microsoft Corporation || Description | ntbios driver || Product |  Microsoft(R) Windows (R) NT Operating System |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ntbios_2.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
