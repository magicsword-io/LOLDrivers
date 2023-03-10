+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "aswVmm.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# aswVmm.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


aswVmm.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create aswVmm.sys binPath=C:\windows\temp\aswVmm.sys type=kernel
sc.exe start aswVmm.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>

<li><a href="https://github.com/tanduRE/AvastHV">https://github.com/tanduRE/AvastHV</a></li>


<br>


##### Known Vulnerable Samples

| Filename: aswVmm.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;aswVmm.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;aswVmm.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;aswVmm.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10&#39;}">36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/aswvmm.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
