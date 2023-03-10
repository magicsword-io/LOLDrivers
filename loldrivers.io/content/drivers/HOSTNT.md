+++

description = "https://github.com/namazso/physmem_drivers"
title = "HOSTNT.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# HOSTNT.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


HOSTNT.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create HOSTNT.sys binPath=C:\windows\temp\HOSTNT.sys type=kernel
sc.exe start HOSTNT.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: HOSTNT.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;HOSTNT.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;07B6D69BAFCFD767F1B63A490A8843C3BB1F8E1BBEA56176109B5743C8F7D357&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;HOSTNT.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;07B6D69BAFCFD767F1B63A490A8843C3BB1F8E1BBEA56176109B5743C8F7D357&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;HOSTNT.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;07B6D69BAFCFD767F1B63A490A8843C3BB1F8E1BBEA56176109B5743C8F7D357&#39;}">07B6D69BAFCFD767F1B63A490A8843C3BB1F8E1BBEA56176109B5743C8F7D357</a>|




### Binary Metadata
<br>

- binary: 
- Verified: 
- Date: 
- Publisher: &#34;SafeNet, Inc.&#34;
- Company: 
- Description: Hostnt 64-bit driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hostnt.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
