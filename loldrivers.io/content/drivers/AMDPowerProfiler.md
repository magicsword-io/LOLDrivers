+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "AMDPowerProfiler.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AMDPowerProfiler.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AMDPowerProfiler.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AMDPowerProfiler.sys binPath=C:\windows\temp\AMDPowerProfiler.sys type=kernel
sc.exe start AMDPowerProfiler.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


##### Known Vulnerable Samples

| Filename: AMDPowerProfiler.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AMDPowerProfiler.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AMDPowerProfiler.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AMDPowerProfiler.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05&#39;}">0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amdpowerprofiler.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
