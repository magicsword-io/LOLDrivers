+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "BSMI.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# BSMI.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


BSMI.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create BSMI.sys binPath=C:\windows\temp\BSMI.sys type=kernel
sc.exe start BSMI.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


##### Known Vulnerable Samples

| Filename: BSMI.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;BSMI.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;BSMI.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;BSMI.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347&#39;}">59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmi.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
