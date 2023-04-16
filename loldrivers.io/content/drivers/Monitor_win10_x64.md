+++

description = ""
title = "Monitor_win10_x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Monitor_win10_x64.sys ![:inline](/images/twitter_verified.png) 


### Description

CVE-2018-16712

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create Monitor_win10_x64.sys binPath=C:\windows\temp\Monitor_win10_x64.sys     type=kernel type=kernel &amp;&amp; sc.exe start Monitor_win10_x64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/244386-mta-fairplaykd-driver-reversed-exploited-rpm.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/244386-mta-fairplaykd-driver-reversed-exploited-rpm.html</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | Monitor_win10_x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/988dabdcf990b134b0ac1e00512c30c4">988dabdcf990b134b0ac1e00512c30c4</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ef80da613442047697bec35ea228cde477c09a3d">ef80da613442047697bec35ea228cde477c09a3d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e4a7da2cf59a4a21fc42b611df1d59cae75051925a7ddf42bf216cc1a026eadb">e4a7da2cf59a4a21fc42b611df1d59cae75051925a7ddf42bf216cc1a026eadb</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%68e5bf10aeb81b2ec77280aec1c2dc22">68e5bf10aeb81b2ec77280aec1c2dc22</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%c42802424a1e61cc089ba1f071734b390232aec3">c42802424a1e61cc089ba1f071734b390232aec3</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%2dec76da0b361e4ed49a4015e67cefb0e6b812103d8ebf93b74016d99d9fcfad">2dec76da0b361e4ed49a4015e67cefb0e6b812103d8ebf93b74016d99d9fcfad</a> || Signature | IObit Information Technology, Symantec Class 3 SHA256 Code Signing CA, VeriSign   || Company | IObit || Description | IObit Temperature Monitor || Product | Advanced SystemCare || OriginalFilename | Monitor.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoCreateDevice
* KeBugCheckEx
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/monitor_win10_x64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
