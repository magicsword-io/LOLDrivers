+++

description = ""
title = "daxin_blank1.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# daxin_blank1.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


Driver used in the Daxin malware campaign.


- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create daxin_blank1.sys binPath=C:\windows\temp\daxin_blank1.sys type=kernel
sc.exe start daxin_blank1.sys
```

### Resources
<br>


<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>

<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>


<br>


##### Known Vulnerable Samples

| Filename: daxin_blank1.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;daxin_blank1.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;daxin_blank1.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;daxin_blank1.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae&#39;}">5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae</a>|




### Binary Metadata
<br>

- binary: 
- Verified: A certificate was explicitly revoked by its issuer.
- Date: 4:05 AM 2/6/2021
- Publisher: Fuqing Yuntan Network Tech Co.,Ltd.
- Company: n/a
- Description: n/a
- Product: n/a
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank1.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
