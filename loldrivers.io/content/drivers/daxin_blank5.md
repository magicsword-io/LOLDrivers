+++

description = ""
title = "daxin_blank5.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank5.sys

#### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create AsrDrv103 binPath= C:\windows\temp\AsrDrv103.sys type= kernel
sc.exe start AsrDrv103.sys
```

#### Resources
<br>


<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>

<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/9c2f3e9811f7d0c7463eaa1ee6f39c23f902f3797b80891590b43bbe0fdf0e51">9c2f3e9811f7d0c7463eaa1ee6f39c23f902f3797b80891590b43bbe0fdf0e51</a></li>



- binary: 
- Verified: Unsigned
- Date: 1:29 AM 7/18/2008
- Publisher: n/a
- Company: n/a
- Description: n/a
- Product: n/a
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank5.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
