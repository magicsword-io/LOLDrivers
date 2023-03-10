+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrAutoChkUpdDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrAutoChkUpdDrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsrAutoChkUpdDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrAutoChkUpdDrv.sys binPath=C:\windows\temp\AsrAutoChkUpdDrv.sys type=kernel
sc.exe start AsrAutoChkUpdDrv.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: AsrAutoChkUpdDrv.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrAutoChkUpdDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrAutoChkUpdDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrAutoChkUpdDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4&#39;}">2AA1B08F47FBB1E2BD2E4A492F5D616968E703E1359A921F62B38B8E4662F0C4</a>|




### Binary Metadata
<br>

- binary: 
- Verified: 
- Date: 
- Publisher: ASROCK Incorporation
- Company: 
- Description: AsrAutoChkUpdDrv Driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrautochkupddrv.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
