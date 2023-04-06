+++

description = ""
title = "elrawdsk.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# elrawdsk.sys ![:inline](/images/twitter_verified.png) 


### Description

elrawdsk.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create elrawdsk.sys binPath=C:\windows\temp\elrawdsk.sys type=kernel
sc.exe start elrawdsk.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://securelist.com/shamoon-the-wiper-further-details-part-ii/57784/">https://securelist.com/shamoon-the-wiper-further-details-part-ii/57784/</a></li>
<li><a href="https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Shamoon.yar">https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Shamoon.yar</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | elrawdsk.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1493d342e7a36553c56b2adea150949e">1493d342e7a36553c56b2adea150949e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ce549714a11bd43b52be709581c6e144957136ec">ce549714a11bd43b52be709581c6e144957136ec</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6">4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6</a> |
| Signature | EldoS Corporation, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Filename | elrawdsk.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/76c643ab29d497317085e5db8c799960">76c643ab29d497317085e5db8c799960</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1292c7dd60214d96a71e7705e519006b9de7968f">1292c7dd60214d96a71e7705e519006b9de7968f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a">5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a</a> |
| Signature | EldoS Corporation, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/elrawdsk.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
