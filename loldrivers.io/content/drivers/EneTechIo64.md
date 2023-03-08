+++

description = "https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"
title = "EneTechIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# EneTechIo64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


EneTechIo64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create EneTechIo64.sys binPath=C:\windows\temp\EneTechIo64.sys type=kernel
sc.exe start EneTechIo64.sys
```

### Resources
<br>


<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>

<li><a href="https://github.com/hfiref0x/KDU/releases/tag/v1.2.0">https://github.com/hfiref0x/KDU/releases/tag/v1.2.0</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/06bda5a1594f7121acd2efe38ccb617fbc078bb9a70b665a5f5efd70e3013f50">06bda5a1594f7121acd2efe38ccb617fbc078bb9a70b665a5f5efd70e3013f50</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/enetechio64.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
