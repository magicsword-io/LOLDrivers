+++

description = ""
title = "Sense5Ext.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Sense5Ext.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f9844524fb0009e5b784c21c7bad4220.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create Sense5Ext.sys binPath=C:\windows\temp\Sense5Ext.sys type=kernel &amp;&amp; sc.exe start Sense5Ext.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | Sense5Ext.sys |
| MD5                | [f9844524fb0009e5b784c21c7bad4220](https://www.virustotal.com/gui/file/f9844524fb0009e5b784c21c7bad4220) |
| SHA1               | [e6765d8866cad6193df1507c18f31fa7f723ca3e](https://www.virustotal.com/gui/file/e6765d8866cad6193df1507c18f31fa7f723ca3e) |
| SHA256             | [7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6](https://www.virustotal.com/gui/file/7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6) |
| Authentihash MD5   | [0b2ce413f69677a0bf78a40ed0d081a7](https://www.virustotal.com/gui/search/authentihash%253A0b2ce413f69677a0bf78a40ed0d081a7) |
| Authentihash SHA1  | [af83d2f800c68099976dcf75ee31681708d32ed9](https://www.virustotal.com/gui/search/authentihash%253Aaf83d2f800c68099976dcf75ee31681708d32ed9) |
| Authentihash SHA256| [13cd99ff2120d9fd651814d826b6c8481d549f684a8fbfb2d8775c9faa1c27f5](https://www.virustotal.com/gui/search/authentihash%253A13cd99ff2120d9fd651814d826b6c8481d549f684a8fbfb2d8775c9faa1c27f5) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |
| Company           | Sense5 CORP |
| Description       | Sense5 Driver |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* ntoskrnl.exe
* HAL.dll
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoGetCurrentProcess
* ObReferenceObjectByHandle
* ObfDereferenceObject
* PsGetCurrentProcessId
* NtBuildNumber
* RtlTimeToTimeFields
* ExSystemTimeToLocalTime
* ZwCreateFile
* ZwWriteFile
* ZwClose
* _snprintf
* _vsnprintf
* ZwQueryInformationFile
* ZwReadFile
* strcmp
* strncmp
* RtlCompareMemory
* RtlImageNtHeader
* RtlCompareUnicodeString
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* isupper
* isdigit
* tolower
* strlen
* _stricmp
* strstr
* wcscat
* wcslen
* RtlInitAnsiString
* RtlQueryRegistryValues
* RtlAnsiStringToUnicodeString
* RtlCompareUnicodeStrings
* ExAllocatePool
* MmGetSystemRoutineAddress
* PsCreateSystemThread
* PsTerminateSystemThread
* PsSetCreateProcessNotifyRoutineEx
* PsSetLoadImageNotifyRoutine
* PsRemoveLoadImageNotifyRoutine
* ZwOpenProcess
* PsGetProcessPeb
* PsGetProcessSessionId
* RtlRandomEx
* KeBugCheckEx
* RtlInitUnicodeString
* _stricmp
* NtQuerySystemInformation
* ZwClose
* ZwQueryValueKey
* ZwOpenKey
* RtlInitUnicodeString
* ZwWaitForSingleObject
* ZwDeviceIoControlFile
* ZwOpenFile
* _wcsnicmp
* ZwEnumerateKey
* ZwCreateEvent
* MmGetSystemRoutineAddress
* ZwCreateFile
* __C_specific_handler
* KeSetSystemAffinityThread
* KeQueryActiveProcessors
* KeQueryTimeIncrement
* DbgBreakPointWithStatus
* RtlTimeToTimeFields
* ExSystemTimeToLocalTime
* IoAllocateMdl
* IoFreeMdl
* MmUnlockPages
* MmMapLockedPagesSpecifyCache
* MmProbeAndLockPages
* KeWaitForSingleObject
* KeReleaseMutex
* KeInitializeMutex
* ExFreePoolWithTag
* ExAllocatePool
* KeRevertToUserAffinityThread
* DbgPrint
* KeQueryPerformanceCounter
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/sense5ext.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
