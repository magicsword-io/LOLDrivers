+++

description = ""
title = "POORTRY.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# POORTRY.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create POORTRY.sys binPath=C:\windows\temp\POORTRY.sys type=kernel
sc.exe start POORTRY.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | POORTRY.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/7f9309f5e4defec132b622fadbcad511">7f9309f5e4defec132b622fadbcad511</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a3ed5cbfbc17b58243289f3cf575bf04be49591d">a3ed5cbfbc17b58243289f3cf575bf04be49591d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6b5cf41512255237064e9274ca8f8a3fef820c45aa6067c9c6a0e6f5751a0421">6b5cf41512255237064e9274ca8f8a3fef820c45aa6067c9c6a0e6f5751a0421</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/poortry.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
