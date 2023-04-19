+++

description = ""
title = "POORTRY2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# POORTRY2.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b164daf106566f444dfb280d743bc2f7.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create POORTRY2.sys binPath=C:\windows\temp\POORTRY2.sys type=kernel &amp;&amp; sc.exe start POORTRY2.sys
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
| Filename           | POORTRY2.sys |
| MD5                | [b164daf106566f444dfb280d743bc2f7](https://www.virustotal.com/gui/file/b164daf106566f444dfb280d743bc2f7) |
| SHA1               | [7e836dadc2e149a0b758c7e22c989cbfcce18684](https://www.virustotal.com/gui/file/7e836dadc2e149a0b758c7e22c989cbfcce18684) |
| SHA256             | [9bb09752cf3a464455422909edef518ac18fe63cf5e1e8d9d6c2e68db62e0c87](https://www.virustotal.com/gui/file/9bb09752cf3a464455422909edef518ac18fe63cf5e1e8d9d6c2e68db62e0c87) |
| Authentihash MD5   | [ffbbaeada1f7507faca4ef59c6e3e577](https://www.virustotal.com/gui/search/authentihash%253Affbbaeada1f7507faca4ef59c6e3e577) |
| Authentihash SHA1  | [56f9aa37f099409170b4656079edbf52e464b700](https://www.virustotal.com/gui/search/authentihash%253A56f9aa37f099409170b4656079edbf52e464b700) |
| Authentihash SHA256| [29bf8618816bce5fa2845409d98b7b96915e0763bb04719535ca885e4713cfaf](https://www.virustotal.com/gui/search/authentihash%253A29bf8618816bce5fa2845409d98b7b96915e0763bb04719535ca885e4713cfaf) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* FLTMGR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlTimeToTimeFields
* ExAllocatePoolWithTag
* ZwCreateKey
* ExFreePoolWithTag
* NtQuerySystemInformation
* ZwReadFile
* RtlInitUnicodeString
* IoCreateFile
* RtlUnicodeStringToAnsiString
* _wcslwr
* IoFileObjectType
* ZwCreateFile
* wcsstr
* ZwQueryValueKey
* ExAllocatePool
* PsTerminateSystemThread
* ZwClose
* RtlFreeAnsiString
* ZwQueryInformationFile
* KeWaitForMultipleObjects
* ZwWriteFile
* _vsnprintf
* KeBugCheck
* DbgPrint
* PsGetCurrentProcessId
* memmove
* ZwAllocateVirtualMemory
* atoi
* _strlwr
* NtQueryInformationProcess
* DbgBreakPoint
* ZwOpenProcess
* KeServiceDescriptorTable
* strrchr
* ObQueryNameString
* NtOpenThread
* NtClose
* NtOpenProcess
* ExSystemTimeToLocalTime
* RtlFreeUnicodeString
* KeQuerySystemTime
* RtlInitAnsiString
* MmGetSystemRoutineAddress
* RtlAnsiStringToUnicodeString
* sprintf
* swprintf_s
* ObfDereferenceObject
* KeSetEvent
* KeWaitForSingleObject
* ObReferenceObjectByHandle
* PsCreateSystemThread
* KeInitializeEvent
* PsSetCreateProcessNotifyRoutineEx
* _except_handler3
* memcpy
* memset
* FltStartFiltering
* FltRegisterFilter
* FltBuildDefaultSecurityDescriptor
* FltCloseCommunicationPort
* FltUnregisterFilter
* FltFreeSecurityDescriptor
* FltCreateCommunicationPort
* FltCloseClientPort

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/poortry2.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
