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


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
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

| Filename | NalDrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1898ceda3247213c084f43637ef163b3">1898ceda3247213c084f43637ef163b3</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d04e5db5b6c848a29732bfd52029001f23c3da75">d04e5db5b6c848a29732bfd52029001f23c3da75</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b">4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%1789a16d20ca2b55f491ad71848166a2">1789a16d20ca2b55f491ad71848166a2</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%2cbfe4ad0e1231ff3e19c19ca9311d952ce170b7">2cbfe4ad0e1231ff3e19c19ca9311d952ce170b7</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%785e87bc23a1353fe0726554fd009aca69c320a98445a604a64e23ab45108087">785e87bc23a1353fe0726554fd009aca69c320a98445a604a64e23ab45108087</a> || Signature | Intel Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | Intel Corporation  || Description | Intel(R) Network Adapter Diagnostic Driver || Product | Intel(R) iQVW64.SYS || OriginalFilename | iQVW64.SYS |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* IoCreateSymbolicLink
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
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/naldrv.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
