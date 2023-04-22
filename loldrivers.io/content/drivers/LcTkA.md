+++

description = ""
title = "LcTkA.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LcTkA.sys ![:inline](/images/twitter_verified.png) 


### Description

SentinelOne has observed prominent threat actors abusing legitimately signed Microsoft drivers in active intrusions into telecommunication, BPO, MSSP, and financial services businesses.
Investigations into these intrusions led to the discovery of POORTRY and STONESTOP malware, part of a small toolkit designed to terminate AV and EDR processes.
We first reported our discovery to Microsoft’s Security Response Center (MSRC) in October 2022 and received an official case number (75361). Today, MSRC released an associated advisory under ADV220005.
This research is being released alongside Mandiant, a SentinelOne technology and incident response partner. 

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/909f3fc221acbe999483c87d9ead024a.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create LcTkA.sys binPath=C:\windows\temp\LcTkA.sys type=kernel &amp;&amp; sc.exe start LcTkA.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/">https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | LcTkA.sys |
| MD5                | [909f3fc221acbe999483c87d9ead024a](https://www.virustotal.com/gui/file/909f3fc221acbe999483c87d9ead024a) |
| SHA1               | [b2f955b3e6107f831ebe67997f8586d4fe9f3e98](https://www.virustotal.com/gui/file/b2f955b3e6107f831ebe67997f8586d4fe9f3e98) |
| SHA256             | [c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497](https://www.virustotal.com/gui/file/c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497) |
| Authentihash MD5   | [b663d79a688800d84065ccc2809874b7](https://www.virustotal.com/gui/search/authentihash%253Ab663d79a688800d84065ccc2809874b7) |
| Authentihash SHA1  | [46a9d9e9904ba5f4c011ad69d0795969c721c662](https://www.virustotal.com/gui/search/authentihash%253A46a9d9e9904ba5f4c011ad69d0795969c721c662) |
| Authentihash SHA256| [675329ef7a63a7c58d3daa6cb5c6e299143decec7a149c36a6bfe204bbf0407e](https://www.virustotal.com/gui/search/authentihash%253A675329ef7a63a7c58d3daa6cb5c6e299143decec7a149c36a6bfe204bbf0407e) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeInitializeEvent
* HalReturnToFirmware
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lctka.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
