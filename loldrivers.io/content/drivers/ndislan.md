+++

description = ""
title = "ndislan.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ndislan.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/47e6ac52431ca47da17248d80bf71389.bin" "Download" >}}
{{< tip "warning" >}}
{% if driver.Category == "vulnerable driver" %}
This download link contains the vulnerable driver!
{% elif driver.Category == "malicious" %}
This download link contains the malicious driver!
{% endif %}
{{< /tip >}}

### Commands

```
sc.exe create ndislan.sys binPath=C:\windows\temp \n \n \n  dislan.sys type=kernel &amp;&amp; sc.exe start ndislan.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48">https://gist.github.com/MHaggis/9ab3bb795a6018d70fb11fa7c31f8f48</a></li>
<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage">https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | ndislan.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/47e6ac52431ca47da17248d80bf71389">47e6ac52431ca47da17248d80bf71389</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d417c0be261b0c6f44afdec3d5432100e420c3ed">d417c0be261b0c6f44afdec3d5432100e420c3ed</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b0eb4d999e4e0e7c2e33ff081e847c87b49940eb24a9e0794c6aa9516832c427">b0eb4d999e4e0e7c2e33ff081e847c87b49940eb24a9e0794c6aa9516832c427</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A8bddebd3670d9f154318afd62195a2b8">8bddebd3670d9f154318afd62195a2b8</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A7f57424f2ce7186e3a1951f3710f28d7ce9c8a96">7f57424f2ce7186e3a1951f3710f28d7ce9c8a96</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9345c3af554c06aa949492f1642a7a03404956d2952cca8a68658b62dccb0825">9345c3af554c06aa949492f1642a7a03404956d2952cca8a68658b62dccb0825</a> || Publisher | Anhua Xinda (Beijing) Technology Co., Ltd. || Signature | A,  , r, e, q, u, i, r, e, d,  , c, e, r, t, i, f, i, c, a, t, e,  , i, s,  , n, o, t,  , w, i, t, h, i, n,  , i, t, s,  , v, a, l, i, d, i, t, y,  , p, e, r, i, o, d,  , w, h, e, n,  , v, e, r, i, f, y, i, n, g,  , a, g, a, i, n, s, t,  , t, h, e,  , c, u, r, r, e, n, t,  , s, y, s, t, e, m,  , c, l, o, c, k,  , o, r,  , t, h, e,  , t, i, m, e, s, t, a, m, p,  , i, n,  , t, h, e,  , s, i, g, n, e, d,  , f, i, l, e, .   || Date | 4:49 PM 10/12/2012 || Company | Microsoft Corporation || Description | MS LAN Driver || Product | Microsoft® Windows® Operating System || OriginalFilename | ndislan.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmUnmapLockedPages
* RtlInitUnicodeString
* RtlUnicodeStringToAnsiString
* IoFreeMdl
* strncpy
* MmMapLockedPagesSpecifyCache
* ZwQueryValueKey
* ZwFreeVirtualMemory
* IofCompleteRequest
* RtlFreeAnsiString
* MmProbeAndLockPages
* MmUnlockPages
* strrchr
* IoAllocateMdl
* ZwAllocateVirtualMemory
* ZwOpenKey
* RtlAnsiStringToUnicodeString
* _stricmp
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* NtQuerySystemInformation
* MmGetSystemRoutineAddress
* RtlImageDirectoryEntryToData
* ObMakeTemporaryObject
* RtlInitAnsiString
* RtlFreeUnicodeString
* IoDriverObjectType
* ObfDereferenceObject
* IoCreateDriver
* ObReferenceObjectByName
* __C_specific_handler
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ndislan.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
