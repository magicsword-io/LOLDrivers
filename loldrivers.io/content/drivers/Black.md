+++

description = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"
title = "Black.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# Black.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


Black.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create Black.sys binPath=C:\windows\temp\Black.sys type=kernel
sc.exe start Black.sys
```

### Resources
<br>


<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>


<br>


##### Known Vulnerable Samples

| Filename: Black.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;Black.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;D5562FB90B0B3DEB633AB335BCBD82CE10953466A428B3F27CB5B226B453EAF3&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;Black.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;D5562FB90B0B3DEB633AB335BCBD82CE10953466A428B3F27CB5B226B453EAF3&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;Black.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;D5562FB90B0B3DEB633AB335BCBD82CE10953466A428B3F27CB5B226B453EAF3&#39;}">D5562FB90B0B3DEB633AB335BCBD82CE10953466A428B3F27CB5B226B453EAF3</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/black.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
