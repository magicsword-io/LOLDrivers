+++

description = ""
title = "wantd_6.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_6.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create wantd_6.sys binPath=C:\windows\temp\wantd_6.sys type=kernel
sc.exe start wantd_6.sys
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

| Filename | wantd_6.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e">e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e</a> |
| Publisher | Anhua Xinda (Beijing) Technology Co., Ltd. |
| Signature | The digital signature of the object did not verify. |
| Date | 8:23 PM 2/28/2022 |
| Company | Microsoft Corporation |
| Description | WAN Transport Driver |
| Product | Microsoft Windows Operating System |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| SOriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_6.sys.yml)

*last_updated:* 2023-03-10








{{< /column >}}
{{< /block >}}
