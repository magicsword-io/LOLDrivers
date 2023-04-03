+++

description = "https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"
title = "NalDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NalDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

NalDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create NalDrv.sys binPath=C:\windows\temp\NalDrv.sys type=kernel
sc.exe start NalDrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Filename | NalDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1898ceda3247213c084f43637ef163b3">1898ceda3247213c084f43637ef163b3</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d04e5db5b6c848a29732bfd52029001f23c3da75">d04e5db5b6c848a29732bfd52029001f23c3da75</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b">4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b</a> |
| Signature | Intel Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/naldrv.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
