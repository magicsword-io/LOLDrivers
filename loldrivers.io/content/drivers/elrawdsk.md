+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "elrawdsk.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# elrawdsk.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


elrawdsk.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create elrawdsk.sys binPath=C:\windows\temp\elrawdsk.sys type=kernel
sc.exe start elrawdsk.sys
```

### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>

<li><a href="https://securelist.com/shamoon-the-wiper-further-details-part-ii/57784/">https://securelist.com/shamoon-the-wiper-further-details-part-ii/57784/</a></li>

<li><a href="https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Shamoon.yar">https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Shamoon.yar</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6">4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6</a></li>

<li><a href="https://www.virustotal.com/gui/file/5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a">5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/elrawdsk.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
