+++

description = ""
title = "HWiNFO64A.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# HWiNFO64A.sys ![:inline](/images/twitter_verified.png) 



### Description


CVE-2018-8061


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create HWiNFO64A.sys binPath=C:\windows\temp\HWiNFO64A.sys type=kernel
sc.exe start HWiNFO64A.sys
```

### Resources
<br>

<br>


### Binary Metadata
<br>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwinfo64a.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
