+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "NTIOLib_X64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NTIOLib_X64.sys

#### Description

NTIOLib_X64.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create NTIOLib_X64.sys binPath= C:\windows\temp\NTIOLib_X64.sys type= kernel
sc.exe start NTIOLib_X64.sys
```

#### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/d8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530">d8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ntiolib_x64.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
