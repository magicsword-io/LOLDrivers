+++

description = "https://github.com/namazso/physmem_drivers"
title = "WinRing0.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# WinRing0.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


WinRing0.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create WinRing0.sys binPath=C:\windows\temp\WinRing0.sys type=kernel
sc.exe start WinRing0.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: WinRing0.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;3EC5AD51E6879464DFBCCB9F4ED76C6325056A42548D5994BA869DA9C4C039A8&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;3EC5AD51E6879464DFBCCB9F4ED76C6325056A42548D5994BA869DA9C4C039A8&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;3EC5AD51E6879464DFBCCB9F4ED76C6325056A42548D5994BA869DA9C4C039A8&#39;}">3EC5AD51E6879464DFBCCB9F4ED76C6325056A42548D5994BA869DA9C4C039A8</a>|

| Filename: WinRing0.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;47EAEBC920CCF99E09FC9924FEB6B19B8A28589F52783327067C9B09754B5E84&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;47EAEBC920CCF99E09FC9924FEB6B19B8A28589F52783327067C9B09754B5E84&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;47EAEBC920CCF99E09FC9924FEB6B19B8A28589F52783327067C9B09754B5E84&#39;}">47EAEBC920CCF99E09FC9924FEB6B19B8A28589F52783327067C9B09754B5E84</a>|

| Filename: WinRing0.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;A7B000ABBCC344444A9B00CFADE7AA22AB92CE0CADEC196C30EB1851AE4FA062&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;A7B000ABBCC344444A9B00CFADE7AA22AB92CE0CADEC196C30EB1851AE4FA062&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;WinRing0.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;A7B000ABBCC344444A9B00CFADE7AA22AB92CE0CADEC196C30EB1851AE4FA062&#39;}">A7B000ABBCC344444A9B00CFADE7AA22AB92CE0CADEC196C30EB1851AE4FA062</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winring0.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
