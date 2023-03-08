+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsUpIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsUpIO.sys ![:inline](/images/twitter_verified.png) 



### Description


AsUpIO.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsUpIO.sys binPath=C:\windows\temp\AsUpIO.sys type=kernel
sc.exe start AsUpIO.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/B9A4E40A5D80FEDD1037EAED958F9F9EFED41EB01ADA73D51B5DCD86E27E0CBF">B9A4E40A5D80FEDD1037EAED958F9F9EFED41EB01ADA73D51B5DCD86E27E0CBF</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asupio.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
