+++

description = ""
title = "Air_SYSTEM10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Air_SYSTEM10.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-03
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Air_SYSTEM10.sys binPath=C:\windows\temp\Air_SYSTEM10.sys type=kernel
sc.exe start Air_SYSTEM10.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<br>

### Known Vulnerable Samples

| Filename | Air_SYSTEM10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1f2888e57fdd6aee466962c25ba7d62d">1f2888e57fdd6aee466962c25ba7d62d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c23eeb6f18f626ce1fd840227f351fa7543bb167">c23eeb6f18f626ce1fd840227f351fa7543bb167</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f461414a2596555cece5cfee65a3c22648db0082ca211f6238af8230e41b3212">f461414a2596555cece5cfee65a3c22648db0082ca211f6238af8230e41b3212</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/air_system10.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
