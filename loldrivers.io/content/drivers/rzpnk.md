+++

description = ""
title = "rzpnk.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rzpnk.sys ![:inline](/images/twitter_verified.png) 


### Description

A vulnerability exists in the latest version of Razer Synapse (v2.20.15.1104 as of the day of disclosure) which can be leveraged locally by a malicious application to elevate its privileges to those of NT_AUTHORITY\SYSTEM. The vulnerability lies in a specific IOCTL handler in the rzpnk.sys driver that passes a PID specified by the user to ZwOpenProcess. CVE-2017-9769.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4cc3ddd5ae268d9a154a426af2c23ef9.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create rzpnk.sys binPath=C:\windows\temp\rzpnk.sys type=kernel &amp;&amp; sc.exe start rzpnk.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/nomi-sec/PoC-in-GitHub/blob/2a85c15ed806287861a7adec6545c85aec618e3b/2017/CVE-2017-9769.json#L13">https://github.com/nomi-sec/PoC-in-GitHub/blob/2a85c15ed806287861a7adec6545c85aec618e3b/2017/CVE-2017-9769.json#L13</a></li>
<li><a href="https://www.rapid7.com/db/modules/exploit/windows/local/razer_zwopenprocess/">https://www.rapid7.com/db/modules/exploit/windows/local/razer_zwopenprocess/</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | rzpnk.sys |
| MD5                | [4cc3ddd5ae268d9a154a426af2c23ef9](https://www.virustotal.com/gui/file/4cc3ddd5ae268d9a154a426af2c23ef9) |
| SHA1               | [684786de4b3b3f53816eae9df5f943a22c89601f](https://www.virustotal.com/gui/file/684786de4b3b3f53816eae9df5f943a22c89601f) |
| SHA256             | [93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63](https://www.virustotal.com/gui/file/93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63) |
| Authentihash MD5   | [76934be6e996e801ea4d68c504d427c3](https://www.virustotal.com/gui/search/authentihash%253A76934be6e996e801ea4d68c504d427c3) |
| Authentihash SHA1  | [b2e03d9e602a6026f45c08b686c6810abd43bfac](https://www.virustotal.com/gui/search/authentihash%253Ab2e03d9e602a6026f45c08b686c6810abd43bfac) |
| Authentihash SHA256| [982ad43111d8b7a7900df652c8873eeb6aa485bb429dee6c2ad44acf598bb5e6](https://www.virustotal.com/gui/search/authentihash%253A982ad43111d8b7a7900df652c8873eeb6aa485bb429dee6c2ad44acf598bb5e6) |
| Signature         | Razer USA Ltd., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
| Company           | Razer, Inc. |
| Description       | Razer Overlay Support |
| Product           | Rzpnk |
| OriginalFilename  | Rzpnk.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoAcquireCancelSpinLock
* IoReleaseCancelSpinLock
* ObReferenceObjectByHandle
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* KeAcquireGuardedMutex
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* IoCreateDevice
* IoCreateSymbolicLink
* PoStartNextPowerIrp
* IoDeleteDevice
* KeInitializeEvent
* PsSetCreateProcessNotifyRoutine
* PsSetCreateThreadNotifyRoutine
* PsRemoveCreateThreadNotifyRoutine
* ZwSetEvent
* _wcslwr
* wcsstr
* ZwClose
* KeSetEvent
* ZwWaitForSingleObject
* _purecall
* KeGetCurrentThread
* _vsnprintf
* swprintf
* PsLookupProcessByProcessId
* PsReferencePrimaryToken
* SeQueryInformationToken
* RtlLengthRequiredSid
* RtlInitializeSid
* RtlSubAuthoritySid
* RtlEqualSid
* PsDereferencePrimaryToken
* MmGetSystemRoutineAddress
* MmIsAddressValid
* KeStackAttachProcess
* KeUnstackDetachProcess
* wcsrchr
* ZwOpenProcess
* PsLookupThreadByThreadId
* ObOpenObjectByPointer
* PsThreadType
* ZwCreateEvent
* PsGetCurrentProcessId
* ZwOpenProcessTokenEx
* ZwQueryInformationToken
* RtlSubAuthorityCountSid
* KeTickCount
* KeBugCheckEx
* ObfDereferenceObject
* sprintf
* IofCompleteRequest
* memcpy
* memset
* RtlUnwind
* KfAcquireSpinLock
* ExReleaseFastMutex
* ExAcquireFastMutex
* KfReleaseSpinLock

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rzpnk.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
