+++

description = ""
title = "daxin_blank2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank2.sys

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



<li><a href="https://www.virustotal.com/gui/file/5c1585b1a1c956c7755429544f3596515dfdf928373620c51b0606a520c6245a">5c1585b1a1c956c7755429544f3596515dfdf928373620c51b0606a520c6245a</a></li>



- binary: 
- Verified: A certificate was explicitly revoked by its issuer.
- Date: 4:05 AM 2/6/2021
- Publisher: Fuqing Yuntan Network Tech Co.,Ltd.
- Company: n/a
- Description: n/a
- Product: n/a
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank2.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
