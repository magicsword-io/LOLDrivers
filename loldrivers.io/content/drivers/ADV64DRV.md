+++

description = "https://github.com/namazso/physmem_drivers"
title = "ADV64DRV.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# ADV64DRV.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


ADV64DRV.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create ADV64DRV.sys binPath=C:\windows\temp\ADV64DRV.sys type=kernel
sc.exe start ADV64DRV.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: ADV64DRV.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;ADV64DRV.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;ADV64DRV.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;ADV64DRV.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162&#39;}">04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162</a>|




### Binary Metadata
<br>

- binary: 
- Verified: 
- Date: 01:30 AM 08/29/2006
- Publisher: FUJITSU LIMITED
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: ADV64DRV.sys

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/adv64drv.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
