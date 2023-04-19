+++

description = ""
title = "NalDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NalDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

NalDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1898ceda3247213c084f43637ef163b3.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create NalDrv.sys binPath=C:\windows\temp\NalDrv.sys type=kernel &amp;&amp; sc.exe start NalDrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c"> https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<li><a href="https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c">https://gist.github.com/k4nfr3/af970e7facb09195e56f2112e1c9549c</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | NalDrv.sys |
| MD5                | [1898ceda3247213c084f43637ef163b3](https://www.virustotal.com/gui/file/1898ceda3247213c084f43637ef163b3) |
| SHA1               | [d04e5db5b6c848a29732bfd52029001f23c3da75](https://www.virustotal.com/gui/file/d04e5db5b6c848a29732bfd52029001f23c3da75) |
| SHA256             | [4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b](https://www.virustotal.com/gui/file/4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b) |
| Authentihash MD5   | [1789a16d20ca2b55f491ad71848166a2](https://www.virustotal.com/gui/search/authentihash%253A1789a16d20ca2b55f491ad71848166a2) |
| Authentihash SHA1  | [2cbfe4ad0e1231ff3e19c19ca9311d952ce170b7](https://www.virustotal.com/gui/search/authentihash%253A2cbfe4ad0e1231ff3e19c19ca9311d952ce170b7) |
| Authentihash SHA256| [785e87bc23a1353fe0726554fd009aca69c320a98445a604a64e23ab45108087](https://www.virustotal.com/gui/search/authentihash%253A785e87bc23a1353fe0726554fd009aca69c320a98445a604a64e23ab45108087) |
| Signature         | Intel Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Intel Corporation  |
| Description       | Intel(R) Network Adapter Diagnostic Driver |
| Product           | Intel(R) iQVW64.SYS |
| OriginalFilename  | iQVW64.SYS |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmGetPhysicalAddress
* DbgPrint
* strncpy
* vsprintf
* IoFreeMdl
* MmMapLockedPagesSpecifyCache
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmUnmapIoSpace
* MmUnmapLockedPages
* MmAllocateContiguousMemory
* MmFreeContiguousMemory
* RtlInitUnicodeString
* ObfDereferenceObject
* KeWaitForSingleObject
* IofCallDriver
* IoBuildSynchronousFsdRequest
* KeInitializeEvent
* ZwClose
* RtlFreeAnsiString
* strstr
* RtlUnicodeStringToAnsiString
* ZwEnumerateValueKey
* ZwOpenKey
* wcsncpy
* IoGetDeviceObjectPointer
* IoGetDeviceInterfaces
* ObReferenceObjectByPointer
* KeBugCheckEx
* IoDeleteSymbolicLink
* MmMapIoSpace
* IoDeleteDevice
* KeStallExecutionProcessor
* KeQueryPerformanceCounter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/naldrv.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
