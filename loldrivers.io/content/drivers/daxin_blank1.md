+++

description = ""
title = "daxin_blank1.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank1.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a6e9d6505f6d2326a8a9214667c61c67.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create daxin_blank1.sys binPath=C:\windows\temp\daxin_blank1.sys     type=kernel &amp;&amp; sc.exe start daxin_blank1.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | daxin_blank1.sys |
| MD5                | [a6e9d6505f6d2326a8a9214667c61c67](https://www.virustotal.com/gui/file/a6e9d6505f6d2326a8a9214667c61c67) |
| SHA1               | [cb3f30809b05cf02bc29d4a7796fb0650271e542](https://www.virustotal.com/gui/file/cb3f30809b05cf02bc29d4a7796fb0650271e542) |
| SHA256             | [5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae](https://www.virustotal.com/gui/file/5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae) |
| Authentihash MD5   | [7c9b3308f3eb98dd7ddb59b2f6b14656](https://www.virustotal.com/gui/search/authentihash%253A7c9b3308f3eb98dd7ddb59b2f6b14656) |
| Authentihash SHA1  | [6a9693e262ea82a33b6caee0426512f944366577](https://www.virustotal.com/gui/search/authentihash%253A6a9693e262ea82a33b6caee0426512f944366577) |
| Authentihash SHA256| [389d04a947be32b43eab5767f548fc193e9ac5fe5225a3b6dc26ddc80c326d7d](https://www.virustotal.com/gui/search/authentihash%253A389d04a947be32b43eab5767f548fc193e9ac5fe5225a3b6dc26ddc80c326d7d) |
| Publisher         | Fuqing Yuntan Network Tech Co.,Ltd. |
| Signature         | A,  , c, e, r, t, i, f, i, c, a, t, e,  , w, a, s,  , e, x, p, l, i, c, i, t, l, y,  , r, e, v, o, k, e, d,  , b, y,  , i, t, s,  , i, s, s, u, e, r, .   |
| Date                | 4:05 AM 2/6/2021 |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* NDIS.SYS
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* _stricmp
* NdisDeregisterProtocol
* ExAllocatePool
* NtQuerySystemInformation
* ExFreePoolWithTag
* IoAllocateMdl
* MmProbeAndLockPages
* MmMapLockedPagesSpecifyCache
* MmUnlockPages
* IoFreeMdl
* KeQueryActiveProcessors
* KeSetSystemAffinityThread
* KeRevertToUserAffinityThread
* DbgPrint
* KeQueryPerformanceCounter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank1.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
