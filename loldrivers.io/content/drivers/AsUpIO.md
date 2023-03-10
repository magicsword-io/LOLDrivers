+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsUpIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsUpIO.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




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


##### Known Vulnerable Samples

| Filename: AsUpIO.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsUpIO.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;B9A4E40A5D80FEDD1037EAED958F9F9EFED41EB01ADA73D51B5DCD86E27E0CBF&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsUpIO.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;B9A4E40A5D80FEDD1037EAED958F9F9EFED41EB01ADA73D51B5DCD86E27E0CBF&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsUpIO.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;B9A4E40A5D80FEDD1037EAED958F9F9EFED41EB01ADA73D51B5DCD86E27E0CBF&#39;}">B9A4E40A5D80FEDD1037EAED958F9F9EFED41EB01ADA73D51B5DCD86E27E0CBF</a>|




### Binary Metadata
<br>

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

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
