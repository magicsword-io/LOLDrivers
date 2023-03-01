+++

description = ""
title = "ntbios_2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ntbios_2.sys

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



<li><a href="https://www.virustotal.com/gui/file/c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c">c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c</a></li>



- binary: 
- Verified: Unsigned
- Date: 3:04 AM 5/18/2009
- Publisher: n/a
- Company: Microsoft Corporation
- Description: ntbios driver
- Product:  Microsoft(R) Windows (R) NT Operating System
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ntbios_2.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
