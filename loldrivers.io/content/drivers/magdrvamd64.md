+++

description = ""
title = "magdrvamd64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# magdrvamd64.sys ![:inline](/images/twitter_verified.png) 


### Description

magdrvamd64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/49938383844ceec33dba794fb751c9a5.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create magdrvamd64.sys binPath=C:\windows\temp\magdrvamd64.sys     type=kernel &amp;&amp; sc.exe start magdrvamd64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | magdrvamd64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/49938383844ceec33dba794fb751c9a5">49938383844ceec33dba794fb751c9a5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e22495d92ac3dcae5eeb1980549a9ead8155f98a">e22495d92ac3dcae5eeb1980549a9ead8155f98a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57">be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A4bc9c678b740fdbb6da3da4af3444c09">4bc9c678b740fdbb6da3da4af3444c09</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A592989e3e6942baf38127b50e39dd732b323a92d">592989e3e6942baf38127b50e39dd732b323a92d</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A911e01544557544de4ad59b374f1234513821c50a00c7afa62a8fcca07385b2f">911e01544557544de4ad59b374f1234513821c50a00c7afa62a8fcca07385b2f</a> || Signature | Samsung Electronics Co., Ltd., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   |
#### Imports
{{< details "Expand" >}}* NTOSKRNL.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IofCompleteRequest
* IoDeleteSymbolicLink
* MmUnmapIoSpace
* MmMapIoSpace
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/magdrvamd64.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
