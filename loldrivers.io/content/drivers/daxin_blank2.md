+++

description = ""
title = "daxin_blank2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# daxin_blank2.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver used in the Daxin malware campaign.

- **Created**: 2023-02-28
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1cd158a64f3d886357535382a6fdad75.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create daxin_blank2.sys binPath=C:\windows\temp\daxin_blank2.sys     type=kernel &amp;&amp; sc.exe start daxin_blank2.sys
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
| Filename           | daxin_blank2.sys |
| MD5                | [1cd158a64f3d886357535382a6fdad75](https://www.virustotal.com/gui/file/1cd158a64f3d886357535382a6fdad75) |
| SHA1               | [a48aa80942fc8e0699f518de4fd6512e341d4196](https://www.virustotal.com/gui/file/a48aa80942fc8e0699f518de4fd6512e341d4196) |
| SHA256             | [5c1585b1a1c956c7755429544f3596515dfdf928373620c51b0606a520c6245a](https://www.virustotal.com/gui/file/5c1585b1a1c956c7755429544f3596515dfdf928373620c51b0606a520c6245a) |
| Authentihash MD5   | [9853eedacdfe3384f34b8eaa771f4f70](https://www.virustotal.com/gui/search/authentihash%253A9853eedacdfe3384f34b8eaa771f4f70) |
| Authentihash SHA1  | [d7254e751cd3a49176a547a5bb70f8a0662d8d28](https://www.virustotal.com/gui/search/authentihash%253Ad7254e751cd3a49176a547a5bb70f8a0662d8d28) |
| Authentihash SHA256| [4b10f4f03eaa545d2fdb3b88890917a6fa24142689d3c43a7c39fc5bed5725bf](https://www.virustotal.com/gui/search/authentihash%253A4b10f4f03eaa545d2fdb3b88890917a6fa24142689d3c43a7c39fc5bed5725bf) |
| Publisher         | Fuqing Yuntan Network Tech Co.,Ltd. |
| Signature         | A,  , c, e, r, t, i, f, i, c, a, t, e,  , w, a, s,  , e, x, p, l, i, c, i, t, l, y,  , r, e, v, o, k, e, d,  , b, y,  , i, t, s,  , i, s, s, u, e, r, .   |
| Date                | 4:05 AM 2/6/2021 |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* NDIS.SYS
* ntoskrnl.exe
* hal.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* vsprintf
* NdisMSendNetBufferListsComplete
* IoAllocateMdl
* MmProbeAndLockPages
* MmMapLockedPagesSpecifyCache
* MmUnlockPages
* IoFreeMdl
* ExAllocatePool
* ExFreePool
* NtQuerySystemInformation
* HalMakeBeep

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/daxin_blank2.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
