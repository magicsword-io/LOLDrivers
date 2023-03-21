+++

description = ""
title = "daxin_blank3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank3.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create daxin_blank3.sys binPath=C:\windows\temp\daxin_blank3.sys type=kernel
sc.exe start daxin_blank3.sys
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

| Filename | daxin_blank3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7a7e8df7173387aec593e4fe2b45520ea3156c5f810d2bb1b2784efd1c922376">7a7e8df7173387aec593e4fe2b45520ea3156c5f810d2bb1b2784efd1c922376</a> |
| Publisher | n/a |
| Signature | Unsigned |
| Date | 12:54 AM 11/18/2009 |
| Company | n/a |
| Description | n/a |
| Product | n/a |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank3.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
