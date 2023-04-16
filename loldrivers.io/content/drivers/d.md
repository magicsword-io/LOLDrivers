+++

description = ""
title = "d.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# d.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

d.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create d.sys binPath=C:\windows\temp\d.sys type=kernel &amp;&amp; sc.exe start d.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Filename | d.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a60c9173563b940203cf4ad38ccf2082">a60c9173563b940203cf4ad38ccf2082</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a3636986cdcd1d1cb8ab540f3d5c29dcc90bb8f0">a3636986cdcd1d1cb8ab540f3d5c29dcc90bb8f0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c1c4310e5d467d24e864177bdbfc57cb5d29aac697481bfa9c11ddbeebfd4cc8">c1c4310e5d467d24e864177bdbfc57cb5d29aac697481bfa9c11ddbeebfd4cc8</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%19dd018ebddfa9044b05fbb9ddffd7f9">19dd018ebddfa9044b05fbb9ddffd7f9</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%80111a99c4f127cca12f1902ca241b3e65f339ff">80111a99c4f127cca12f1902ca241b3e65f339ff</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%a4ca4a0932afa09e8df3469768f5ac6feaff2b7ae27ac208a218288fc4fbf102">a4ca4a0932afa09e8df3469768f5ac6feaff2b7ae27ac208a218288fc4fbf102</a> || Signature | -   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* KeInitializeEvent
* ObReferenceObjectByHandle
* ZwClose
* ObfDereferenceObject
* PsCreateSystemThread
* IoGetCurrentProcess
* _stricmp
* strchr
* ZwCreateFile
* RtlInitUnicodeString
* ZwReadFile
* ZwQueryInformationFile
* KeDetachProcess
* ProbeForRead
* ZwQueryInformationProcess
* KeAttachProcess
* KeLeaveCriticalRegion
* KeEnterCriticalRegion
* ObOpenObjectByName
* KeServiceDescriptorTable
* KeAddSystemServiceTable
* PsGetCurrentProcessId
* ProbeForWrite
* wcsstr
* ObQueryNameString
* IoFileObjectType
* SeSinglePrivilegeCheck
* KeGetPreviousMode
* KeDelayExecutionThread
* ZwAllocateVirtualMemory
* ZwQuerySection
* ExfInterlockedInsertTailList
* ExFreePoolWithTag
* sprintf
* RtlVolumeDeviceToDosName
* IoGetDeviceObjectPointer
* MmSectionObjectType
* strstr
* _strlwr
* PsProcessType
* PsSetCreateProcessNotifyRoutine
* KeInitializeSpinLock
* PsThreadType
* PsTerminateSystemThread
* vsprintf
* KeQuerySystemTime
* ExfInterlockedRemoveHeadList
* NtBuildNumber
* ExAllocatePoolWithTag
* ZwOpenKey
* ZwEnumerateKey
* ZwDeleteKey
* _except_handler3
* swprintf
* _wcsnicmp
* ZwQuerySystemInformation
* PsLookupProcessByProcessId
* wcstombs
* ExAcquireFastMutex
* ExReleaseFastMutex
* KfAcquireSpinLock
* KfReleaseSpinLock
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/d.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
