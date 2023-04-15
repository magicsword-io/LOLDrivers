+++

description = ""
title = "Sense5Ext.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Sense5Ext.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Sense5Ext.sys binPath=C:\windows\temp\Sense5Ext.sys type=kernel &amp;&amp; sc.exe start Sense5Ext.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | Sense5Ext.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f9844524fb0009e5b784c21c7bad4220">f9844524fb0009e5b784c21c7bad4220</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e6765d8866cad6193df1507c18f31fa7f723ca3e">e6765d8866cad6193df1507c18f31fa7f723ca3e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6">7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   || Company | Sense5 CORP || Description | Sense5 Driver |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sense5ext.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
