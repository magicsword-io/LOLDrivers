+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "procexp.Sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# procexp.Sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


procexp.Sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create procexp.Sys binPath=C:\windows\temp\procexp.Sys type=kernel
sc.exe start procexp.Sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


##### Known Vulnerable Samples

| Filename: procexp.Sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;procexp.Sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;procexp.Sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;procexp.Sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c&#39;}">440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/procexp.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
