+++

description = ""
title = "wantd_6.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# wantd_6.sys

#### Description


Driver used in the Daxin malware campaign.


- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create wantd_6.sys binPath= C:\windows\temp\wantd_6.sys type= kernel
sc.exe start wantd_6.sys
```

#### Resources
<br>


<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>

<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e">e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e</a></li>



- binary: 
- Verified: The digital signature of the object did not verify.
- Date: 8:23 PM 2/28/2022
- Publisher: Anhua Xinda (Beijing) Technology Co., Ltd.
- Company: Microsoft Corporation
- Description: WAN Transport Driver
- Product: Microsoft Windows Operating System
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/wantd_6.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
