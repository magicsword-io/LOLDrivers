+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "kEvP64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# kEvP64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


kEvP64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create kEvP64.sys binPath=C:\windows\temp\kEvP64.sys type=kernel
sc.exe start kEvP64.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


##### Known Vulnerable Samples

| Filename: kEvP64.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;kEvP64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;kEvP64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;kEvP64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c&#39;}">1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/kevp64.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
