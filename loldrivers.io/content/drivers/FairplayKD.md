+++

description = ""
title = "FairplayKD.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# FairplayKD.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

FairplayKD.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4e90cd77509738d30d3181a4d0880bfa.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create FairplayKD.sys binPath=C:\windows\temp\FairplayKD.sys type=kernel &amp;&amp; sc.exe start FairplayKD.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/244386-mta-fairplaykd-driver-reversed-exploited-rpm.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/244386-mta-fairplaykd-driver-reversed-exploited-rpm.html</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | FairplayKD.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4e90cd77509738d30d3181a4d0880bfa">4e90cd77509738d30d3181a4d0880bfa</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b4dcdbd97f38b24d729b986f84a9cdb3fc34d59f">b4dcdbd97f38b24d729b986f84a9cdb3fc34d59f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9f4ce6ab5e8d44f355426d9a6ab79833709f39b300733b5b251a0766e895e0e5">9f4ce6ab5e8d44f355426d9a6ab79833709f39b300733b5b251a0766e895e0e5</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A5fb82230ba512d33a6e3090985a29e49">5fb82230ba512d33a6e3090985a29e49</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253A0eaa4cf7d1944f6259dd9941209dec15a4029c4a">0eaa4cf7d1944f6259dd9941209dec15a4029c4a</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253A66d59e646f3965bc5225eca4285ae65f34b8681fb1bee3eaf440f6795b2fa70f">66d59e646f3965bc5225eca4285ae65f34b8681fb1bee3eaf440f6795b2fa70f</a> || Signature | Hans Roes, Thawte Code Signing CA - G2, thawte   || Company | Multi Theft Auto || Description | Multi Theft Auto patch driver || Product | MTA San Andreas |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* PsProcessType
* RtlAnsiStringToUnicodeString
* KeUnstackDetachProcess
* ObReferenceObjectByHandle
* KeStackAttachProcess
* RtlInitUnicodeString
* PsThreadType
* PsGetThreadProcessId
* MmGetSystemRoutineAddress
* _vsnwprintf
* RtlCompareUnicodeString
* RtlCompareMemory
* RtlCopyUnicodeString
* RtlGetVersion
* MmUnmapLockedPages
* ExAllocatePoolWithTag
* ProbeForRead
* ExRaiseStatus
* ExFreePoolWithTag
* ProbeForWrite
* MmHighestUserAddress
* MmMapLockedPagesSpecifyCache
* IoGetCurrentProcess
* MmProbeAndLockPages
* MmUnlockPages
* MmIsAddressValid
* ObfDereferenceObject
* KeBugCheckEx
* PsGetVersion
* ExAllocatePoolWithQuotaTag
* ZwQuerySystemInformation
* __C_specific_handler
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fairplaykd.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
