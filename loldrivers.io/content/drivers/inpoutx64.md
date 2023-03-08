+++

description = "https://github.com/namazso/physmem_drivers"
title = "inpoutx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# inpoutx64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


inpoutx64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create inpoutx64.sys binPath=C:\windows\temp\inpoutx64.sys type=kernel
sc.exe start inpoutx64.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/2D83CCB1AD9839C9F5B3F10B1F856177DF1594C66CBBC7661677D4B462EBF44D">2D83CCB1AD9839C9F5B3F10B1F856177DF1594C66CBBC7661677D4B462EBF44D</a></li>

<li><a href="https://www.virustotal.com/gui/file/F581DECC2888EF27EE1EA85EA23BBB5FB2FE6A554266FF5A1476ACD1D29D53AF">F581DECC2888EF27EE1EA85EA23BBB5FB2FE6A554266FF5A1476ACD1D29D53AF</a></li>

<li><a href="https://www.virustotal.com/gui/file/F8965FDCE668692C3785AFA3559159F9A18287BC0D53ABB21902895A8ECF221B">F8965FDCE668692C3785AFA3559159F9A18287BC0D53ABB21902895A8ECF221B</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/inpoutx64.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
