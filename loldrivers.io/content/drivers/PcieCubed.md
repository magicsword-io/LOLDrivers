+++

description = ""
title = "PcieCubed.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# PcieCubed.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


Driver categorized as POORTRY by Mandiant.


- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create PcieCubed.sys binPath=C:\windows\temp\PcieCubed.sys type=kernel
sc.exe start PcieCubed.sys
```

### Resources
<br>


<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/22949977ce5cd96ba674b403a9c81285">22949977ce5cd96ba674b403a9c81285</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: 
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/pciecubed.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
