+++

description = ""
title = "daxin_blank4.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# daxin_blank4.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




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
sc.exe create daxin_blank4.sys binPath=C:\windows\temp\daxin_blank4.sys type=kernel
sc.exe start daxin_blank4.sys
```

### Resources
<br>


<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>

<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e">8dafe5f3d0527b66f6857559e3c81872699003e0f2ffda9202a1b5e29db2002e</a></li>



- binary: 
- Verified: Unsigned
- Date: 8:42 AM 4/20/2010
- Publisher: n/a
- Company: n/a
- Description: n/a
- Product: n/a
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank4.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}