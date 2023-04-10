+++

description = ""
title = "DBUtilDrv2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# DBUtilDrv2.sys ![:inline](/images/twitter_verified.png) 


### Description

DBUtilDrv2.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create DBUtilDrv2.sys binPath=C:\windows\temp\DBUtilDrv2.sys type=kernel &amp;&amp; sc.exe start DBUtilDrv2.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | DBUtilDrv2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/dacb62578b3ea191ea37486d15f4f83c">dacb62578b3ea191ea37486d15f4f83c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/90a76945fd2fa45fab2b7bcfdaf6563595f94891">90a76945fd2fa45fab2b7bcfdaf6563595f94891</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8">2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   || Filename | DBUtilDrv2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d104621c93213942b7b43d65b5d8d33e">d104621c93213942b7b43d65b5d8d33e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b03b1996a40bfea72e4584b82f6b845c503a9748">b03b1996a40bfea72e4584b82f6b845c503a9748</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009">71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutildrv2.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
