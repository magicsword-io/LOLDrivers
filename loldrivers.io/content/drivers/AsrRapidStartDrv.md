+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrRapidStartDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrRapidStartDrv.sys ![:inline](/images/twitter_verified.png) 



### Description


AsrRapidStartDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrRapidStartDrv.sys binPath=C:\windows\temp\AsrRapidStartDrv.sys type=kernel
sc.exe start AsrRapidStartDrv.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/0AAFA9F47ACF69D46C9542985994FF5321F00842A28DF2396D4A3076776A83CB">0AAFA9F47ACF69D46C9542985994FF5321F00842A28DF2396D4A3076776A83CB</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrrapidstartdrv.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
