+++

description = ""
title = "NBIOLib_X64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NBIOLib_X64.sys ![:inline](/images/twitter_verified.png) 


### Description

NBIOLib_X64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create NBIOLib_X64.sys binPath=C:\windows\temp\NBIOLib_X64.sys     type=kernel type=kernel &amp;&amp; sc.exe start NBIOLib_X64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | NBIOLib_X64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f2f728d2f69765f5dfda913d407783d2">f2f728d2f69765f5dfda913d407783d2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/35829e096a15e559fcbabf3441d99e580ca3b26e">35829e096a15e559fcbabf3441d99e580ca3b26e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3f2fda9a7a9c57b7138687bbce49a2e156d6095dddabb3454ea09737e02c3fa5">3f2fda9a7a9c57b7138687bbce49a2e156d6095dddabb3454ea09737e02c3fa5</a> |
| Signature | MICRO-STAR INTERNATIONAL CO., LTD., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nbiolib_x64.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
