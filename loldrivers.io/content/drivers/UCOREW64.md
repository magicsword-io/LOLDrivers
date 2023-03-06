+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "UCOREW64.SYS"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# UCOREW64.SYS 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


UCOREW64.SYS is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create UCOREW64.SYS binPath=C:\windows\temp\UCOREW64.SYS type=kernel
sc.exe start UCOREW64.SYS
```

### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200">a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ucorew64.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
