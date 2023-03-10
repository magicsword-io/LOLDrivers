+++

description = "https://github.com/namazso/physmem_drivers"
title = "iomem64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# iomem64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


iomem64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create iomem64.sys binPath=C:\windows\temp\iomem64.sys type=kernel
sc.exe start iomem64.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: iomem64.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;iomem64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;3D23BDBAF9905259D858DF5BF991EB23D2DC9F4ECDA7F9F77839691ACEF1B8C4&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;iomem64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;3D23BDBAF9905259D858DF5BF991EB23D2DC9F4ECDA7F9F77839691ACEF1B8C4&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;iomem64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;3D23BDBAF9905259D858DF5BF991EB23D2DC9F4ECDA7F9F77839691ACEF1B8C4&#39;}">3D23BDBAF9905259D858DF5BF991EB23D2DC9F4ECDA7F9F77839691ACEF1B8C4</a>|

| Filename: iomem64.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;iomem64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;DD4A1253D47DE14EF83F1BC8B40816A86CCF90D1E624C5ADF9203AE9D51D4097&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;iomem64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;DD4A1253D47DE14EF83F1BC8B40816A86CCF90D1E624C5ADF9203AE9D51D4097&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;iomem64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;DD4A1253D47DE14EF83F1BC8B40816A86CCF90D1E624C5ADF9203AE9D51D4097&#39;}">DD4A1253D47DE14EF83F1BC8B40816A86CCF90D1E624C5ADF9203AE9D51D4097</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iomem64.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
