+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsIO.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsIO.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsIO.sys binPath=C:\windows\temp\AsIO.sys type=kernel
sc.exe start AsIO.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/2DA330A2088409EFC351118445A824F11EDBE51CF3D653B298053785097FE40E">2DA330A2088409EFC351118445A824F11EDBE51CF3D653B298053785097FE40E</a></li>

<li><a href="https://www.virustotal.com/gui/file/436CCAB6F62FA2D29827916E054ADE7ACAE485B3DE1D3E5C6C62D3DEBF1480E7,hash:B4D47EA790920A4531E3DF5A4B4B0721B7FEA6B49A35679F0652F1E590422602">436CCAB6F62FA2D29827916E054ADE7ACAE485B3DE1D3E5C6C62D3DEBF1480E7,hash:B4D47EA790920A4531E3DF5A4B4B0721B7FEA6B49A35679F0652F1E590422602</a></li>

<li><a href="https://www.virustotal.com/gui/file/DDE6F28B3F7F2ABBEE59D4864435108791631E9CB4CDFB1F178E5AA9859956D8">DDE6F28B3F7F2ABBEE59D4864435108791631E9CB4CDFB1F178E5AA9859956D8</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asio.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
