+++

description = "https://github.com/Chigusa0w0/AsusDriversPrivEscala"
title = "driver7-x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# driver7-x64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


driver7-x64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create driver7-x64.sys binPath=C:\windows\temp\driver7-x64.sys type=kernel
sc.exe start driver7-x64.sys
```

### Resources
<br>


<li><a href=" https://github.com/Chigusa0w0/AsusDriversPrivEscala"> https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>


<br>


##### Known Vulnerable Samples

| Filename: driver7-x64.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;driver7-x64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;771A8D05F1AF6214E0EF0886662BE500EE910AB99F0154227067FDDCFE08A3DD&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;driver7-x64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;771A8D05F1AF6214E0EF0886662BE500EE910AB99F0154227067FDDCFE08A3DD&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;driver7-x64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;771A8D05F1AF6214E0EF0886662BE500EE910AB99F0154227067FDDCFE08A3DD&#39;}">771A8D05F1AF6214E0EF0886662BE500EE910AB99F0154227067FDDCFE08A3DD</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x64.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
