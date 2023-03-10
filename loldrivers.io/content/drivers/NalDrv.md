+++

description = "https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"
title = "NalDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# NalDrv.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


NalDrv.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create NalDrv.sys binPath=C:\windows\temp\NalDrv.sys type=kernel
sc.exe start NalDrv.sys
```

### Resources
<br>


<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>


<br>


##### Known Vulnerable Samples

| Filename: NalDrv.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;NalDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;NalDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;NalDrv.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b&#39;}">4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/naldrv.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
