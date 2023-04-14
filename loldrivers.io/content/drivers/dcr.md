+++

description = ""
title = "dcr.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dcr.sys ![:inline](/images/twitter_verified.png) 


### Description

DriveCrypt Dcr.sys vulnerability exploit for bypassing x64 DSE

- **Created**: 2023-04-14
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create dcr.sys binPath=C:\windows\temp\dcr.sys type=kernel &amp;&amp; sc.exe start dcr.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/wjcsharp/DriveCrypt">https://github.com/wjcsharp/DriveCrypt</a></li>
<br>

### Known Vulnerable Samples

| Filename | dcr.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c24800c382b38707e556af957e9e94fd">c24800c382b38707e556af957e9e94fd</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b49ac8fefc6d1274d84fef44c1e5183cc7accba1">b49ac8fefc6d1274d84fef44c1e5183cc7accba1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3c6f9917418e991ed41540d8d882c8ca51d582a82fd01bff6cdf26591454faf5">3c6f9917418e991ed41540d8d882c8ca51d582a82fd01bff6cdf26591454faf5</a> |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dcr.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
