+++

description = ""
title = "speedfan.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# speedfan.sys ![:inline](/images/twitter_verified.png) 


### Description

speedfan.sys is a vulnerable driver. CVE-2007-5633.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create speedfan.sys binPath=C:\windows\temp\speedfan.sys type=kernel &amp;&amp; sc.exe start speedfan.sys
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

| Filename | speedfan.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5f9785e7535f8f602cb294a54962c9e7">5f9785e7535f8f602cb294a54962c9e7</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bfe55cacc7c56c9f7bd75bdb4b352c0b745d071b">bfe55cacc7c56c9f7bd75bdb4b352c0b745d071b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c">22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%af368f76c059d1e07aa884e86d29bbab">af368f76c059d1e07aa884e86d29bbab</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%9c08d169b0f59a411c5b51f481622bc78bdf9c84">9c08d169b0f59a411c5b51f481622bc78bdf9c84</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%641490e28b2a1ee223238f5d969b5abf60a1089afe597c4251b285449e6b3b04">641490e28b2a1ee223238f5d969b5abf60a1089afe597c4251b285449e6b3b04</a> || Signature | Sokno S.R.L., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | Windows (R) Server 2003 DDK provider || Description | SpeedFan Device Driver || Product | Windows (R) Server 2003 DDK driver || OriginalFilename | speedfan.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* PsGetVersion
* IoCreateDevice
* RtlUnwindEx
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/speedfan.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
