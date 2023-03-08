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

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create wantd_3.sys binPath=C:\windows\temp\wantd_3.sys type=kernel
sc.exe start wantd_3.sys
```

### Resources
<br>


<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>

<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1">81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1</a></li>



- binary: 
- Verified: Unsigned
- Date: 7:52 AM 4/30/2014
- Publisher: n/a
- Company: Microsoft Corporation
- Description: WAN Transport Driver
- Product: Microsoft Windows Operating System
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_3.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
