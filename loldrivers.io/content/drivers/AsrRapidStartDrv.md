+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrRapidStartDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrRapidStartDrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsrRapidStartDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrRapidStartDrv.sys binPath=C:\windows\temp\AsrRapidStartDrv.sys type=kernel
sc.exe start AsrRapidStartDrv.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: AsrRapidStartDrv.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrRapidStartDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;0AAFA9F47ACF69D46C9542985994FF5321F00842A28DF2396D4A3076776A83CB&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrRapidStartDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;0AAFA9F47ACF69D46C9542985994FF5321F00842A28DF2396D4A3076776A83CB&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrRapidStartDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;0AAFA9F47ACF69D46C9542985994FF5321F00842A28DF2396D4A3076776A83CB&#39;}">0AAFA9F47ACF69D46C9542985994FF5321F00842A28DF2396D4A3076776A83CB</a>|




### Binary Metadata
<br>

- binary: 
- Verified: 
- Date: 
- Publisher: ASROCK Incorporation
- Company: 
- Description: RW-Everything Read &amp; Write Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrrapidstartdrv.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
