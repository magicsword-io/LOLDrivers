+++

description = ""
title = "EneIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# EneIo64.sys ![:inline](/images/twitter_verified.png) 


### Description

EneIo64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create EneIo64.sys binPath=C:\windows\temp\EneIo64.sys type=kernel
sc.exe start EneIo64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<li><a href="https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c">https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Filename | EneIo64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/11fb599312cb1cf43ca5e879ed6fb71e">11fb599312cb1cf43ca5e879ed6fb71e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b4d014b5edd6e19ce0e8395a64faedf49688ecb5">b4d014b5edd6e19ce0e8395a64faedf49688ecb5</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374">9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/eneio64.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
