+++

description = ""
title = "2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mhyprot3.sys


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

mhyprot3.sys is a vulnerable driver and more information will be added as found.
- **UUID**: 2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5cc5c26fc99175997d84fe95c61ab2c2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create mhyprot3.sys binPath=C:\windows\temp\mhyprot3.sys type=kernel &amp;&amp; sc.exe start mhyprot3.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | mhyprot3.sys |
| MD5                | [5cc5c26fc99175997d84fe95c61ab2c2](https://www.virustotal.com/gui/file/5cc5c26fc99175997d84fe95c61ab2c2) |
| SHA1               | [a197a02025946aca96d6e74746f84774df31249e](https://www.virustotal.com/gui/file/a197a02025946aca96d6e74746f84774df31249e) |
| SHA256             | [475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a](https://www.virustotal.com/gui/file/475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a) |
| Authentihash MD5   | [7ce959fb5b40f1ba40bcac22c8d95c75](https://www.virustotal.com/gui/search/authentihash%253A7ce959fb5b40f1ba40bcac22c8d95c75) |
| Authentihash SHA1  | [82fe9b69f358ef5851eeaa26a9a03f2e1b231358](https://www.virustotal.com/gui/search/authentihash%253A82fe9b69f358ef5851eeaa26a9a03f2e1b231358) |
| Authentihash SHA256| [aac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8](https://www.virustotal.com/gui/search/authentihash%253Aaac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8) |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExReleaseFastMutex
* ObfDereferenceObject
* PsLookupProcessByProcessId
* NtQuerySystemInformation
* RtlInitUnicodeString
* KeSetEvent
* KeEnterCriticalRegion
* KeLeaveCriticalRegion
* KeWaitForSingleObject
* ExAllocatePoolWithTag
* ExInitializeResourceLite
* ExAcquireResourceExclusiveLite
* ExReleaseResourceLite
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetCurrentProcess
* ObReferenceObjectByHandle
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* MmIsAddressValid
* PsGetCurrentProcessId
* MmCopyVirtualMemory
* vsprintf_s
* swprintf_s
* ExEventObjectType
* _wcsicmp
* RtlInitString
* RtlAnsiStringToUnicodeString
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* ZwOpenDirectoryObject
* ZwQueryDirectoryObject
* ObReferenceObjectByName
* ZwQuerySystemInformation
* __C_specific_handler
* MmHighestUserAddress
* IoDriverObjectType
* KeQueryTimeIncrement
* KeStackAttachProcess
* KeUnstackDetachProcess
* PsGetProcessWow64Process
* PsGetProcessPeb
* MmUnlockPages
* ExAcquireFastMutex
* MmUnmapLockedPages
* IoFreeMdl
* ZwTerminateProcess
* PsGetProcessImageFileName
* ZwQueryObject
* ObOpenObjectByPointer
* PsReferenceProcessFilePointer
* IoQueryFileDosDeviceName
* MmProbeAndLockPages
* MmBuildMdlForNonPagedPool
* MmMapLockedPagesSpecifyCache
* IoAllocateMdl
* KeClearEvent
* MmMapLockedPages
* PsSetCreateProcessNotifyRoutineEx
* PsSetCreateThreadNotifyRoutine
* PsRemoveCreateThreadNotifyRoutine
* PsSetLoadImageNotifyRoutine
* PsRemoveLoadImageNotifyRoutine
* RtlUpcaseUnicodeChar
* DbgPrint
* ObRegisterCallbacks
* ObUnRegisterCallbacks
* ObGetFilterVersion
* PsGetProcessId
* IoThreadToProcess
* strcmp
* PsProcessType
* PsThreadType
* RtlEqualUnicodeString
* RtlGetVersion
* ObfReferenceObject
* ObGetObjectType
* ExEnumHandleTable
* ExfUnblockPushLock
* PsAcquireProcessExitSynchronization
* PsReleaseProcessExitSynchronization
* _snprintf
* ZwCreateFile
* ZwWriteFile
* PsLookupThreadByThreadId
* NtQueryInformationThread
* PsGetThreadProcess
* KeDelayExecutionThread
* KdDisableDebugger
* KdChangeOption
* PsCreateSystemThread
* PsTerminateSystemThread
* KdDebuggerEnabled
* PsGetVersion
* RtlCopyUnicodeString
* ExFreePoolWithTag
* ExAllocatePool
* KeInitializeEvent
* MmGetSystemRoutineAddress
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}

#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00"
    },
    {
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00"
    },
    {
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00"
    },
    {
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00"
    },
    {
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37"
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba"
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3.yaml)

*last_updated:* 2023-05-08








{{< /column >}}
{{< /block >}}
