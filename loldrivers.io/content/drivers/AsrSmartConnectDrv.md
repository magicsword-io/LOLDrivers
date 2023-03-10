+++

description = "https://github.com/namazso/physmem_drivers"
title = "AsrSmartConnectDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# AsrSmartConnectDrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


AsrSmartConnectDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create AsrSmartConnectDrv.sys binPath=C:\windows\temp\AsrSmartConnectDrv.sys type=kernel
sc.exe start AsrSmartConnectDrv.sys
```

### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


##### Known Vulnerable Samples

| Filename: AsrSmartConnectDrv.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrSmartConnectDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;47F08F7D30D824A8F4BB8A98916401A37C0FD8502DB308ABA91FE3112B892DCC&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrSmartConnectDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;47F08F7D30D824A8F4BB8A98916401A37C0FD8502DB308ABA91FE3112B892DCC&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;AsrSmartConnectDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;47F08F7D30D824A8F4BB8A98916401A37C0FD8502DB308ABA91FE3112B892DCC&#39;}">47F08F7D30D824A8F4BB8A98916401A37C0FD8502DB308ABA91FE3112B892DCC</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrsmartconnectdrv.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
