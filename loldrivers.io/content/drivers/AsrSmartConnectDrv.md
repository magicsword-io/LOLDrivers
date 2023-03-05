+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrSmartConnectDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrSmartConnectDrv.sys

#### Description


AsrSmartConnectDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Testing

```
sc.exe create AsrSmartConnectDrv.sys binPath= C:\windows\temp\AsrSmartConnectDrv.sys type= kernel
sc.exe start AsrSmartConnectDrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/47F08F7D30D824A8F4BB8A98916401A37C0FD8502DB308ABA91FE3112B892DCC">47F08F7D30D824A8F4BB8A98916401A37C0FD8502DB308ABA91FE3112B892DCC</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: ASROCK Incorporation
- Company: 
- Description: RW-Everything Read &amp; Write Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrsmartconnectdrv.sys.yml)

*last_updated:* 2023-03-04


{{< /column >}}
{{< /block >}}
