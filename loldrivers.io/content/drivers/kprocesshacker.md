+++

description = ""
title = "kprocesshacker.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# kprocesshacker.sys ![:inline](/images/twitter_verified.png) 


### Description

kprocesshacker.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create kprocesshacker.sys binPath=C:\windows\temp\kprocesshacker.sys     type=kernel type=kernel &amp;&amp; sc.exe start kprocesshacker.sys
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

| Filename | kprocesshacker.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1b5c3c458e31bede55145d0644e88d75">1b5c3c458e31bede55145d0644e88d75</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a21c84c6bf2e21d69fa06daaf19b4cc34b589347">a21c84c6bf2e21d69fa06daaf19b4cc34b589347</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4">70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4</a> |
| Signature | Wen Jia Liu, DigiCert High Assurance Code Signing CA-1, DigiCert   || Company | wj32 || Description | KProcessHacker || Product | KProcessHacker || OriginalFilename | kprocesshacker.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/kprocesshacker.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
