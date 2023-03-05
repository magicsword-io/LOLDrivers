+++

description = ""
title = "wantd.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd.sys

#### Description


Driver used in the Daxin malware campaign.


- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create wantd.sys binPath= C:\windows\temp\wantd.sys type= kernel
sc.exe start wantd.sys
```

#### Resources
<br>


<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>

<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4">06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4</a></li>



- binary: 
- Verified: A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.
- Date: 11:59 PM 11/27/2013
- Publisher: Anhua Xinda (Beijing) Technology Co., Ltd.
- Company: Microsoft Corporation
- Description: WAN Transport Driver
- Product: Microsoft Windows Operating System
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
