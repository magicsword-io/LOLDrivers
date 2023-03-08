+++

description = "https://github.com/namazso/physmem_drivers"
title = "GLCKIO2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# GLCKIO2.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


GLCKIO2.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create GLCKIO2.sys binPath=C:\windows\temp\GLCKIO2.sys type=kernel
sc.exe start GLCKIO2.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/3A5EC83FE670E5E23AEF3AFA0A7241053F5B6BE5E6CA01766D6B5F9177183C25">3A5EC83FE670E5E23AEF3AFA0A7241053F5B6BE5E6CA01766D6B5F9177183C25</a></li>

<li><a href="https://www.virustotal.com/gui/file/61A1BDDDD3C512E681818DEBB5BEE94DB701768FC25E674FCAD46592A3259BD0">61A1BDDDD3C512E681818DEBB5BEE94DB701768FC25E674FCAD46592A3259BD0</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: ASUSTeK Computer Inc.
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/glckio2.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
