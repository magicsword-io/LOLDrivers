+++

description = ""
title = "2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3"
weight = 10
displayTitle = "mhyprot3.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mhyprot3.sys ![:inline](/images/twitter_verified.png) 

### Description

mhyprot3.sys is a vulnerable driver and more information will be added as found.
- **UUID**: 2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5cc5c26fc99175997d84fe95c61ab2c2.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
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



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_drivers_strict.yar" "Exact Match" >}}{{< tip >}}with header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_drivers.yar" "Threat Hunting" >}}{{< tip >}}without header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_drivers_strict_renamed.yar" "Renamed" >}}{{< tip >}}for renamed driver files{{< /tip >}} 


{{< /details >}}
{{< /column >}}



{{< column >}}

#### Sigma 🛡️
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sigma/driver_load_win_vuln_drivers_names.yml" "Names" >}}{{< tip >}}detects loading using name only{{< /tip >}} 


{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sigma/driver_load_win_vuln_drivers.yml" "Hashes" >}}{{< tip >}}detects loading using hashes only{{< /tip >}} 

{{< /details >}}

{{< /column >}}


{{< column "mb-2" >}}

#### Sysmon 🔎
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon/sysmon_config_vulnerable_hashes_block.xml" "Block" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon/sysmon_config_vulnerable_hashes.xml" "Alert" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< /details >}}

{{< /column >}}
{{< /block >}}


### Resources
<br>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | mhyprot3.sys |
| Creation Timestamp           | 2022-02-28 06:09:58 |
| MD5                | [5cc5c26fc99175997d84fe95c61ab2c2](https://www.virustotal.com/gui/file/5cc5c26fc99175997d84fe95c61ab2c2) |
| SHA1               | [a197a02025946aca96d6e74746f84774df31249e](https://www.virustotal.com/gui/file/a197a02025946aca96d6e74746f84774df31249e) |
| SHA256             | [475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a](https://www.virustotal.com/gui/file/475e5016c9c0f5a127896f9179a1b1577a67b357f399ab5a1e68aab07134729a) |
| Authentihash MD5   | [7ce959fb5b40f1ba40bcac22c8d95c75](https://www.virustotal.com/gui/search/authentihash%253A7ce959fb5b40f1ba40bcac22c8d95c75) |
| Authentihash SHA1  | [82fe9b69f358ef5851eeaa26a9a03f2e1b231358](https://www.virustotal.com/gui/search/authentihash%253A82fe9b69f358ef5851eeaa26a9a03f2e1b231358) |
| Authentihash SHA256| [aac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8](https://www.virustotal.com/gui/search/authentihash%253Aaac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5cc5c26fc99175997d84fe95c61ab2c2.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 0d424ae0be3a88ff604021ce1400f0dd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | c0189c338449a42fe8358c2c1fbecc60  |
| ToBeSigned (TBS) SHA1             | b8ac0ee6875594b80ad86a6df6dd1fa3048c187c |
| ToBeSigned (TBS) SHA256           | a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5 |
| Subject                           | C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021 |
| ValidFrom                         | 2021-01-01 00:00:00 |
| ValidTo                           | 2031-01-06 00:00:00 |
| Signature                         | 481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0d424ae0be3a88ff604021ce1400f0dd |
| Version                           | 3 |
###### Certificate 053ad4f9ee8438ef1662ab8d599213ba
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | cf1823794dca38d348ac92962c7d5169  |
| ToBeSigned (TBS) SHA1             | b8e9d958543069fdabf0c237726e0c7cc43b5dfe |
| ToBeSigned (TBS) SHA256           | 86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8 |
| Subject                           | C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd. |
| ValidFrom                         | 2019-04-04 00:00:00 |
| ValidTo                           | 2022-04-08 12:00:00 |
| Signature                         | 6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 053ad4f9ee8438ef1662ab8d599213ba |
| Version                           | 3 |
###### Certificate 0409181b5fd5bb66755343b56f955008
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 9359496ca4f021408b9d8923cab8b179  |
| ToBeSigned (TBS) SHA1             | 2aed40d7759997830870769be250199fd609e40e |
| ToBeSigned (TBS) SHA256           | e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA |
| ValidFrom                         | 2013-10-22 12:00:00 |
| ValidTo                           | 2028-10-22 12:00:00 |
| Signature                         | 3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0409181b5fd5bb66755343b56f955008 |
| Version                           | 3 |
###### Certificate 0aa125d6d6321b7e41e405da3697c215
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8d26184fc613f89aba1cefb30fce1b53  |
| ToBeSigned (TBS) SHA1             | 63a7e376bad5ec2e419d514a403bcf46c8d31d95 |
| ToBeSigned (TBS) SHA256           | 56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA |
| ValidFrom                         | 2016-01-07 12:00:00 |
| ValidTo                           | 2031-01-07 12:00:00 |
| Signature                         | 719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0aa125d6d6321b7e41e405da3697c215 |
| Version                           | 3 |
###### Certificate 611cb28a000000000026
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 983a0c315a50542362f2bd6a5d71c8d0  |
| ToBeSigned (TBS) SHA1             | 8047f476001f5cb16a661d2a3fd0c3576168f5e2 |
| ToBeSigned (TBS) SHA256           | 5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA |
| ValidFrom                         | 2011-04-15 19:41:37 |
| ValidTo                           | 2021-04-15 19:51:37 |
| Signature                         | 5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 611cb28a000000000026 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT
* .upx0
* .reloc
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0d424ae0be3a88ff604021ce1400f0dd",
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "TBS": {
        "MD5": "c0189c338449a42fe8358c2c1fbecc60",
        "SHA1": "b8ac0ee6875594b80ad86a6df6dd1fa3048c187c",
        "SHA256": "a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5",
        "SHA384": "76d3a316a5a106050298418cce3beea16100524723d9e3220b0de51bfb6f1c35a5d4c7cd10b358fef7bf94c3e3562150"
      },
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "TBS": {
        "MD5": "cf1823794dca38d348ac92962c7d5169",
        "SHA1": "b8e9d958543069fdabf0c237726e0c7cc43b5dfe",
        "SHA256": "86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8",
        "SHA384": "50169f7ae27863c5c690fba1e7833c6de342cac8aa6e1abca4da93970425d92468a6e81c255e0fb66146823e5b250fc0"
      },
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0409181b5fd5bb66755343b56f955008",
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "TBS": {
        "MD5": "9359496ca4f021408b9d8923cab8b179",
        "SHA1": "2aed40d7759997830870769be250199fd609e40e",
        "SHA256": "e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65",
        "SHA384": "5cb7e7b4f1dbccd48d10db7e71b6f8c05fcb4bcb0085a6fefcfa0c2148f9a594e59f56ac4304004f3b398e259035c40c"
      },
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0aa125d6d6321b7e41e405da3697c215",
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "TBS": {
        "MD5": "8d26184fc613f89aba1cefb30fce1b53",
        "SHA1": "63a7e376bad5ec2e419d514a403bcf46c8d31d95",
        "SHA256": "56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c",
        "SHA384": "d8c9691fe9dbe182f07b49b07fbb4f589fa7b38b5c4d21f265d3a2e818f4b1bfb39e03faab2ec05bb10333a99914fb8a"
      },
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611cb28a000000000026",
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "TBS": {
        "MD5": "983a0c315a50542362f2bd6a5d71c8d0",
        "SHA1": "8047f476001f5cb16a661d2a3fd0c3576168f5e2",
        "SHA256": "5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83",
        "SHA384": "5f014b60511ddab3247ef0b3c03fe82c622237ba76015e2911d1adc50dc632d56ebd1ee532f3c2b6cbfe68d80a2c91dc"
      },
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2021-12-13 23:25:51 |
| MD5                | [fa63a634189bd4d6570964e2161426b0](https://www.virustotal.com/gui/file/fa63a634189bd4d6570964e2161426b0) |
| SHA1               | [190ec384e6eb1dafca80df05055ead620b2502ba](https://www.virustotal.com/gui/file/190ec384e6eb1dafca80df05055ead620b2502ba) |
| SHA256             | [7fd90500b57f9ac959c87f713fe9ca59e669e6e1512f77fccb6a75cdc0dfee8e](https://www.virustotal.com/gui/file/7fd90500b57f9ac959c87f713fe9ca59e669e6e1512f77fccb6a75cdc0dfee8e) |
| Authentihash MD5   | [50cd2925db0948a464db9993e50bb8bb](https://www.virustotal.com/gui/search/authentihash%253A50cd2925db0948a464db9993e50bb8bb) |
| Authentihash SHA1  | [dbc894f12ad8135ae58149761ce10c41cb3c4757](https://www.virustotal.com/gui/search/authentihash%253Adbc894f12ad8135ae58149761ce10c41cb3c4757) |
| Authentihash SHA256| [bb29eb4651e3276b14217628e96a1e5d83c4e883cd29ebd75aa704dda462e82d](https://www.virustotal.com/gui/search/authentihash%253Abb29eb4651e3276b14217628e96a1e5d83c4e883cd29ebd75aa704dda462e82d) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/fa63a634189bd4d6570964e2161426b0.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 330000004de597a775e3157f7b00000000004d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 9f0782e89bd41cdd96ec55357457478a  |
| ToBeSigned (TBS) SHA1             | 35c2180572baad19019acca1334e6c653699c389 |
| ToBeSigned (TBS) SHA256           | 50814710213afec410f26e573d25267a2e21d3d15f158be8a43a666c9cc6fa08 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2021-09-09 19:15:59 |
| ValidTo                           | 2022-09-01 19:15:59 |
| Signature                         | 1757782e797188079911866d54bd474a2432707984658c549a407e7fb4e5efa2ba72367a02b382d2116d4c4538836ddcd4616fcd231229df1ae5d0da6b3abe499ee5d8b47a7919940f6bbcbe2575018dca65eef4913e3d38410f2cd6cca3082d9ba2c061173cd828635665f76e8f0f685e03da24290b9d2cae7039da974de7b7e85798ba64cbe9ba34e0308c3bd6b4d68e9723fde74274fd3806fe799d04d6a3835f82d4fefc52088ccda4b4c817116f2f5a99445a3e952d78bc27753e65e97c6271c71ac7c9e3439b847e8984ab06a5904d150223f9ca92bbda86c02663c3f4964da5e106619b6eaff2768143cce9e5a8b0b2cba90e82cd87866d9fd6499c6cfbc96529a18b5653d12b54a6c928693a4e3d197ffbfcce7ed71a909b18d09b4345b24bc25eb8dfa1821a9cd0971ffc7d38a26580e2f118c4ac55bf926d0666b72ad7ba6ec20f0b54d694bc3b8a0dbddda27bd64194da085319841d1ebc9dc067ef72ea064a475bea865828b13077bc8e14e2f7544b90f0045f3cd84bcc0d5a80645a6fb65528e4f768ec775bdb0225399f3c81c0b667714676d0949f9ffaddc8549dc45e5ce4345c4ea7dc0aff4ac510f5527ad94a2181edc4b73bcfde813a83d81ca897854c98712346001a12e5d3bf9a45c807f9b3c7d3e0bb99c035ea54ee39e2c9af4147dbea7aabec85b47192b945e083ddf6061afb901e83b11135d24e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 330000004de597a775e3157f7b00000000004d |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* ExReleaseFastMutex
* ObfDereferenceObject
* PsLookupProcessByProcessId
* NtQuerySystemInformation
* RtlInitUnicodeString
* KeSetEvent
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
* MmGetSystemRoutineAddress
* ExAcquireFastMutex
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
* MmUnmapLockedPages
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* PAGE
* INIT
* .upx0
* .reloc
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0d424ae0be3a88ff604021ce1400f0dd",
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "TBS": {
        "MD5": "c0189c338449a42fe8358c2c1fbecc60",
        "SHA1": "b8ac0ee6875594b80ad86a6df6dd1fa3048c187c",
        "SHA256": "a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5",
        "SHA384": "76d3a316a5a106050298418cce3beea16100524723d9e3220b0de51bfb6f1c35a5d4c7cd10b358fef7bf94c3e3562150"
      },
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "TBS": {
        "MD5": "cf1823794dca38d348ac92962c7d5169",
        "SHA1": "b8e9d958543069fdabf0c237726e0c7cc43b5dfe",
        "SHA256": "86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8",
        "SHA384": "50169f7ae27863c5c690fba1e7833c6de342cac8aa6e1abca4da93970425d92468a6e81c255e0fb66146823e5b250fc0"
      },
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0409181b5fd5bb66755343b56f955008",
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "TBS": {
        "MD5": "9359496ca4f021408b9d8923cab8b179",
        "SHA1": "2aed40d7759997830870769be250199fd609e40e",
        "SHA256": "e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65",
        "SHA384": "5cb7e7b4f1dbccd48d10db7e71b6f8c05fcb4bcb0085a6fefcfa0c2148f9a594e59f56ac4304004f3b398e259035c40c"
      },
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0aa125d6d6321b7e41e405da3697c215",
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "TBS": {
        "MD5": "8d26184fc613f89aba1cefb30fce1b53",
        "SHA1": "63a7e376bad5ec2e419d514a403bcf46c8d31d95",
        "SHA256": "56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c",
        "SHA384": "d8c9691fe9dbe182f07b49b07fbb4f589fa7b38b5c4d21f265d3a2e818f4b1bfb39e03faab2ec05bb10333a99914fb8a"
      },
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611cb28a000000000026",
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "TBS": {
        "MD5": "983a0c315a50542362f2bd6a5d71c8d0",
        "SHA1": "8047f476001f5cb16a661d2a3fd0c3576168f5e2",
        "SHA256": "5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83",
        "SHA384": "5f014b60511ddab3247ef0b3c03fe82c622237ba76015e2911d1adc50dc632d56ebd1ee532f3c2b6cbfe68d80a2c91dc"
      },
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2022-02-28 06:09:58 |
| MD5                | [fbf729350ca08a7673b115ce9c9eb7e5](https://www.virustotal.com/gui/file/fbf729350ca08a7673b115ce9c9eb7e5) |
| SHA1               | [5bdd44eb321557c5d3ab056959397f0048ac90e6](https://www.virustotal.com/gui/file/5bdd44eb321557c5d3ab056959397f0048ac90e6) |
| SHA256             | [c3d479d7efd0f6b502d6829b893711bdd51aac07d66326b41ef5451bafdfcb29](https://www.virustotal.com/gui/file/c3d479d7efd0f6b502d6829b893711bdd51aac07d66326b41ef5451bafdfcb29) |
| Authentihash MD5   | [7ce959fb5b40f1ba40bcac22c8d95c75](https://www.virustotal.com/gui/search/authentihash%253A7ce959fb5b40f1ba40bcac22c8d95c75) |
| Authentihash SHA1  | [82fe9b69f358ef5851eeaa26a9a03f2e1b231358](https://www.virustotal.com/gui/search/authentihash%253A82fe9b69f358ef5851eeaa26a9a03f2e1b231358) |
| Authentihash SHA256| [aac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8](https://www.virustotal.com/gui/search/authentihash%253Aaac86a3143de3e18dea6eab813b285da0718e9fb6bc0bbb46c6e7638476061d8) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/fbf729350ca08a7673b115ce9c9eb7e5.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 330000004de597a775e3157f7b00000000004d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 9f0782e89bd41cdd96ec55357457478a  |
| ToBeSigned (TBS) SHA1             | 35c2180572baad19019acca1334e6c653699c389 |
| ToBeSigned (TBS) SHA256           | 50814710213afec410f26e573d25267a2e21d3d15f158be8a43a666c9cc6fa08 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2021-09-09 19:15:59 |
| ValidTo                           | 2022-09-01 19:15:59 |
| Signature                         | 1757782e797188079911866d54bd474a2432707984658c549a407e7fb4e5efa2ba72367a02b382d2116d4c4538836ddcd4616fcd231229df1ae5d0da6b3abe499ee5d8b47a7919940f6bbcbe2575018dca65eef4913e3d38410f2cd6cca3082d9ba2c061173cd828635665f76e8f0f685e03da24290b9d2cae7039da974de7b7e85798ba64cbe9ba34e0308c3bd6b4d68e9723fde74274fd3806fe799d04d6a3835f82d4fefc52088ccda4b4c817116f2f5a99445a3e952d78bc27753e65e97c6271c71ac7c9e3439b847e8984ab06a5904d150223f9ca92bbda86c02663c3f4964da5e106619b6eaff2768143cce9e5a8b0b2cba90e82cd87866d9fd6499c6cfbc96529a18b5653d12b54a6c928693a4e3d197ffbfcce7ed71a909b18d09b4345b24bc25eb8dfa1821a9cd0971ffc7d38a26580e2f118c4ac55bf926d0666b72ad7ba6ec20f0b54d694bc3b8a0dbddda27bd64194da085319841d1ebc9dc067ef72ea064a475bea865828b13077bc8e14e2f7544b90f0045f3cd84bcc0d5a80645a6fb65528e4f768ec775bdb0225399f3c81c0b667714676d0949f9ffaddc8549dc45e5ce4345c4ea7dc0aff4ac510f5527ad94a2181edc4b73bcfde813a83d81ca897854c98712346001a12e5d3bf9a45c807f9b3c7d3e0bb99c035ea54ee39e2c9af4147dbea7aabec85b47192b945e083ddf6061afb901e83b11135d24e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 330000004de597a775e3157f7b00000000004d |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
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
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT
* .upx0
* .reloc
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0d424ae0be3a88ff604021ce1400f0dd",
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "TBS": {
        "MD5": "c0189c338449a42fe8358c2c1fbecc60",
        "SHA1": "b8ac0ee6875594b80ad86a6df6dd1fa3048c187c",
        "SHA256": "a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5",
        "SHA384": "76d3a316a5a106050298418cce3beea16100524723d9e3220b0de51bfb6f1c35a5d4c7cd10b358fef7bf94c3e3562150"
      },
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "TBS": {
        "MD5": "cf1823794dca38d348ac92962c7d5169",
        "SHA1": "b8e9d958543069fdabf0c237726e0c7cc43b5dfe",
        "SHA256": "86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8",
        "SHA384": "50169f7ae27863c5c690fba1e7833c6de342cac8aa6e1abca4da93970425d92468a6e81c255e0fb66146823e5b250fc0"
      },
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0409181b5fd5bb66755343b56f955008",
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "TBS": {
        "MD5": "9359496ca4f021408b9d8923cab8b179",
        "SHA1": "2aed40d7759997830870769be250199fd609e40e",
        "SHA256": "e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65",
        "SHA384": "5cb7e7b4f1dbccd48d10db7e71b6f8c05fcb4bcb0085a6fefcfa0c2148f9a594e59f56ac4304004f3b398e259035c40c"
      },
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0aa125d6d6321b7e41e405da3697c215",
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "TBS": {
        "MD5": "8d26184fc613f89aba1cefb30fce1b53",
        "SHA1": "63a7e376bad5ec2e419d514a403bcf46c8d31d95",
        "SHA256": "56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c",
        "SHA384": "d8c9691fe9dbe182f07b49b07fbb4f589fa7b38b5c4d21f265d3a2e818f4b1bfb39e03faab2ec05bb10333a99914fb8a"
      },
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611cb28a000000000026",
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "TBS": {
        "MD5": "983a0c315a50542362f2bd6a5d71c8d0",
        "SHA1": "8047f476001f5cb16a661d2a3fd0c3576168f5e2",
        "SHA256": "5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83",
        "SHA384": "5f014b60511ddab3247ef0b3c03fe82c622237ba76015e2911d1adc50dc632d56ebd1ee532f3c2b6cbfe68d80a2c91dc"
      },
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2022-05-30 11:28:46 |
| MD5                | [766f9ea38918827df59a6aed204d2b09](https://www.virustotal.com/gui/file/766f9ea38918827df59a6aed204d2b09) |
| SHA1               | [12154f58b68902a40a7165035d37974128deb902](https://www.virustotal.com/gui/file/12154f58b68902a40a7165035d37974128deb902) |
| SHA256             | [24e70c87d58fa5771f02b9ddf0d8870cba6b26e35c6455a2c77f482e2080d3e9](https://www.virustotal.com/gui/file/24e70c87d58fa5771f02b9ddf0d8870cba6b26e35c6455a2c77f482e2080d3e9) |
| Authentihash MD5   | [a5419f516e383eaf16a76174b3a8becd](https://www.virustotal.com/gui/search/authentihash%253Aa5419f516e383eaf16a76174b3a8becd) |
| Authentihash SHA1  | [e19e10d97d7ecd4a4376196f7e3dfa2365872867](https://www.virustotal.com/gui/search/authentihash%253Ae19e10d97d7ecd4a4376196f7e3dfa2365872867) |
| Authentihash SHA256| [5a021532f0ac453256526428ccf3518cdba4c6373cc72f340ba208b6c41b3a9e](https://www.virustotal.com/gui/search/authentihash%253A5a021532f0ac453256526428ccf3518cdba4c6373cc72f340ba208b6c41b3a9e) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/766f9ea38918827df59a6aed204d2b09.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 330000004de597a775e3157f7b00000000004d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 9f0782e89bd41cdd96ec55357457478a  |
| ToBeSigned (TBS) SHA1             | 35c2180572baad19019acca1334e6c653699c389 |
| ToBeSigned (TBS) SHA256           | 50814710213afec410f26e573d25267a2e21d3d15f158be8a43a666c9cc6fa08 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2021-09-09 19:15:59 |
| ValidTo                           | 2022-09-01 19:15:59 |
| Signature                         | 1757782e797188079911866d54bd474a2432707984658c549a407e7fb4e5efa2ba72367a02b382d2116d4c4538836ddcd4616fcd231229df1ae5d0da6b3abe499ee5d8b47a7919940f6bbcbe2575018dca65eef4913e3d38410f2cd6cca3082d9ba2c061173cd828635665f76e8f0f685e03da24290b9d2cae7039da974de7b7e85798ba64cbe9ba34e0308c3bd6b4d68e9723fde74274fd3806fe799d04d6a3835f82d4fefc52088ccda4b4c817116f2f5a99445a3e952d78bc27753e65e97c6271c71ac7c9e3439b847e8984ab06a5904d150223f9ca92bbda86c02663c3f4964da5e106619b6eaff2768143cce9e5a8b0b2cba90e82cd87866d9fd6499c6cfbc96529a18b5653d12b54a6c928693a4e3d197ffbfcce7ed71a909b18d09b4345b24bc25eb8dfa1821a9cd0971ffc7d38a26580e2f118c4ac55bf926d0666b72ad7ba6ec20f0b54d694bc3b8a0dbddda27bd64194da085319841d1ebc9dc067ef72ea064a475bea865828b13077bc8e14e2f7544b90f0045f3cd84bcc0d5a80645a6fb65528e4f768ec775bdb0225399f3c81c0b667714676d0949f9ffaddc8549dc45e5ce4345c4ea7dc0aff4ac510f5527ad94a2181edc4b73bcfde813a83d81ca897854c98712346001a12e5d3bf9a45c807f9b3c7d3e0bb99c035ea54ee39e2c9af4147dbea7aabec85b47192b945e083ddf6061afb901e83b11135d24e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 330000004de597a775e3157f7b00000000004d |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
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
* ExDeleteResourceLite
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
* ExAcquireFastMutex
* MmGetSystemRoutineAddress
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
* MmUnlockPages
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT
* .upx0
* .reloc
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0d424ae0be3a88ff604021ce1400f0dd",
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "TBS": {
        "MD5": "c0189c338449a42fe8358c2c1fbecc60",
        "SHA1": "b8ac0ee6875594b80ad86a6df6dd1fa3048c187c",
        "SHA256": "a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5",
        "SHA384": "76d3a316a5a106050298418cce3beea16100524723d9e3220b0de51bfb6f1c35a5d4c7cd10b358fef7bf94c3e3562150"
      },
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "TBS": {
        "MD5": "cf1823794dca38d348ac92962c7d5169",
        "SHA1": "b8e9d958543069fdabf0c237726e0c7cc43b5dfe",
        "SHA256": "86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8",
        "SHA384": "50169f7ae27863c5c690fba1e7833c6de342cac8aa6e1abca4da93970425d92468a6e81c255e0fb66146823e5b250fc0"
      },
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0409181b5fd5bb66755343b56f955008",
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "TBS": {
        "MD5": "9359496ca4f021408b9d8923cab8b179",
        "SHA1": "2aed40d7759997830870769be250199fd609e40e",
        "SHA256": "e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65",
        "SHA384": "5cb7e7b4f1dbccd48d10db7e71b6f8c05fcb4bcb0085a6fefcfa0c2148f9a594e59f56ac4304004f3b398e259035c40c"
      },
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0aa125d6d6321b7e41e405da3697c215",
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "TBS": {
        "MD5": "8d26184fc613f89aba1cefb30fce1b53",
        "SHA1": "63a7e376bad5ec2e419d514a403bcf46c8d31d95",
        "SHA256": "56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c",
        "SHA384": "d8c9691fe9dbe182f07b49b07fbb4f589fa7b38b5c4d21f265d3a2e818f4b1bfb39e03faab2ec05bb10333a99914fb8a"
      },
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611cb28a000000000026",
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "TBS": {
        "MD5": "983a0c315a50542362f2bd6a5d71c8d0",
        "SHA1": "8047f476001f5cb16a661d2a3fd0c3576168f5e2",
        "SHA256": "5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83",
        "SHA384": "5f014b60511ddab3247ef0b3c03fe82c622237ba76015e2911d1adc50dc632d56ebd1ee532f3c2b6cbfe68d80a2c91dc"
      },
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2021-12-03 02:33:16 |
| MD5                | [00f887e74faad40e6e97d9d0e9c71370](https://www.virustotal.com/gui/file/00f887e74faad40e6e97d9d0e9c71370) |
| SHA1               | [6e58421e37c022410455b1c7b01f1e3c949df1cd](https://www.virustotal.com/gui/file/6e58421e37c022410455b1c7b01f1e3c949df1cd) |
| SHA256             | [b617a072c578cea38c460e2851f3d122ba1b7cfa1f5ee3e9f5927663ac37af61](https://www.virustotal.com/gui/file/b617a072c578cea38c460e2851f3d122ba1b7cfa1f5ee3e9f5927663ac37af61) |
| Authentihash MD5   | [e46017a78ed80d665a2fac51eb5c49f3](https://www.virustotal.com/gui/search/authentihash%253Ae46017a78ed80d665a2fac51eb5c49f3) |
| Authentihash SHA1  | [dba3175fbe67b69a002161d718afb1507d9eb774](https://www.virustotal.com/gui/search/authentihash%253Adba3175fbe67b69a002161d718afb1507d9eb774) |
| Authentihash SHA256| [91793baa79b630f452267c408cc7509f25aa7ac0e39e88576e3daed3dcd5d8e5](https://www.virustotal.com/gui/search/authentihash%253A91793baa79b630f452267c408cc7509f25aa7ac0e39e88576e3daed3dcd5d8e5) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/00f887e74faad40e6e97d9d0e9c71370.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 05a7559541e0fdc678d79e3272468907
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 3e83a7572d1c522dd9072ba6399029d7  |
| ToBeSigned (TBS) SHA1             | e2c2d59b70f028a66a8711bfa97f842475f84639 |
| ToBeSigned (TBS) SHA256           | 5a504a929cb21f72008d5d57bcd992a7cac13f6aa90cbb886b5ecd809e3b59dd |
| Subject                           | C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd. |
| ValidFrom                         | 2019-04-08 00:00:00 |
| ValidTo                           | 2022-04-08 12:00:00 |
| Signature                         | 46a5e6f6c38a63b314f7e2677bb86d4bcd7839eef8e006048ddd58c6783ff0657456e61c800efb31966c611f7ca7d1de1785e006e3f4c0b24cb652842e42cbae016320a774724537fc30e8f09895fdb626daa26b5740c7538aa1df1f97dcab12c3a743c2048f6c9a754f66189ac0f21544399798fb780cd347c9cac0443c8d778736938e17cdd5eca8a2338d8171efd61e13c868dff862da9df4ca8c653a227e0971030aa7e6b44dc2199d1ebd9cae00c6f0a3e91bb883cc509fb297902ba5c13e5826071d92178ace51f1a0653b0445cf7ba17226401c92d7db4f67a37d1243f9094ad5f32873891ea5004a8cbfec77129d4955e344492aaee456f852001ded |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 05a7559541e0fdc678d79e3272468907 |
| Version                           | 3 |
###### Certificate 611cb28a000000000026
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 983a0c315a50542362f2bd6a5d71c8d0  |
| ToBeSigned (TBS) SHA1             | 8047f476001f5cb16a661d2a3fd0c3576168f5e2 |
| ToBeSigned (TBS) SHA256           | 5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA |
| ValidFrom                         | 2011-04-15 19:41:37 |
| ValidTo                           | 2021-04-15 19:51:37 |
| Signature                         | 5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 611cb28a000000000026 |
| Version                           | 3 |
###### Certificate 0fa8490615d700a0be2176fdc5ec6dbd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a9a31555bbc92b6033975c5428fb3679  |
| ToBeSigned (TBS) SHA1             | 47f4b9898631773231b32844ec0d49990ac4eb1e |
| ToBeSigned (TBS) SHA256           | c826846e4b1d73edb7561ab1b41c949354e237a91e82fe1be5b7e2e1701f52d1 |
| Subject                           | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Code Signing CA,1 |
| ValidFrom                         | 2011-02-11 12:00:00 |
| ValidTo                           | 2026-02-10 12:00:00 |
| Signature                         | 7b721d64ff88c83ac1b7e9e7a9c487bbdb9492d7905933fa2b87dea85b80253f138f9b831b7c43c4e68cdf393ec315ecb0da3b21257b24c1725db84791811346fa9c3f6a5138deb425cbf0abdfc528015479104624d1380f26a161904dbabd28e63ff1c4aa9bf6da35534fc9f23dd36cdc23edaaa04d6709f33a803d3cfb364c90e776a4ddf23abf56352fa24c65e8e0d4dad1c7c8916a2d234f373b199418d4d59c103cd5b11c19ff8fc86b9b9ef8ae9c999678d1cd9c51155b4226725a8d0a4a239240e886de22c2933ad49b68a6df297f06b93c0ebd9fc4869c82474271328609997209794b9d7169f541ff7f397764f1848dbe8b1eb27d68a3a590b10cff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 0fa8490615d700a0be2176fdc5ec6dbd |
| Version                           | 3 |
###### Certificate 300f6facdd6698747ca94636a7782db9
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 63499ed59a1293b786649470e4ce0bd7  |
| ToBeSigned (TBS) SHA1             | 7309d8eaa65da1f3da7030c08f00a3b0a20fa908 |
| ToBeSigned (TBS) SHA256           | 8c8d2046b29e792e71b28705fe67c435208a336dde074a75452d98e72c734937 |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Time Stamping CA |
| ValidFrom                         | 2019-05-02 00:00:00 |
| ValidTo                           | 2038-01-18 23:59:59 |
| Signature                         | 6d5481a5335d16e1b553819175df037a320b2d258411b2b0db2a7d2a05f5bc3b27f45aa0b9495990296c61cbb550dbe27df99f00ef40c3add3e2e456f95841cff142e5107dffb0741f8fc65c09f9335eeaa01c26585cf3b4110fd5d5c3e2bcd55878bf4876e144676d8fb043100f8de4f93862bf1301c585a34cc5ccb2533095a4d6f4965608b8cd5c7f0196be72526a3b42377c1678399393949bb1dcb26d416d67cdc96f903d7f4572c11b23d6c2558466e4b3c56606f6f3d64b5eada32b428a2192fea86f5a2570628173635ea0bbd8dcd74ad33daf830638121d24872de4fc02d63e7704bc0436b5e777cb9c2e8d2318b9a3c2471df05dd6a1735705689aa7c937651dbeeabcd842834305a58ba609ffd1a194a64eaa3d09f5056cb7d2645ad82a22c24b9df1395e4cde483d9b34969a095f8efdf7b15291ce3f89f61ca1b5a9751f71bf5b435d653d50816eabf0d0d3fcb2b31fb6999626f43c798b5c64cccdee279ae5a0c00c7287c16e4d5ad31eeaf044e6326f1ceb174e94c37865203b0f41aa1fe9a1419dfeb1b8a0652a34e0dea8f93ce6c130bbc0a0632cfc5c1600a8d0c47fea119d1e06c6a66d325db438092b4907aafdec30daf1a72fcfb7fdfad0a384d9279efb016677b95610e1206ec6aeb1f9b6bac8355d33768ef17c200c2a77aeb5a20286ba29eeb45a00b18cabe3f90ac9545dd4b96a749ebd48ae98 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.12 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 300f6facdd6698747ca94636a7782db9 |
| Version                           | 3 |
###### Certificate 008c77a0008ff4d1b0c63d9f3a48838d6b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 6efd500ce038df7aa3087c1e63a5eb5c  |
| ToBeSigned (TBS) SHA1             | 1c961712a02fb995c585080eda53a753656ca3ad |
| ToBeSigned (TBS) SHA256           | f60d4f8f7b56499de889264b1e64890694c5b106129d3db068976ed33495577a |
| Subject                           | C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Time Stamping Signer #2 |
| ValidFrom                         | 2020-10-23 00:00:00 |
| ValidTo                           | 2032-01-22 23:59:59 |
| Signature                         | 4a0378904233ec7b1a830936339855bb9d4006306b456af1940e1950ff5b255e3be139c45bbae995903737bddffb64ece582b795cc5755704b4ef4a887dd2285a657bbb82127d4a02a31948a07219e8abda71af50215cb4450998cec3eba0377a6820290c22e93a9be21347563b9e02d0fcf0137cb8da2fab85a9aaea17a9e139319558f09902edfea881716eb69d6e125bd45089780d75420284fca7bb3b3a5d200b0603465c4e3c5c3a5e4ba85aa7a69db75a43e79689a368b43ae36d461723c0e85620da05e70db642f01c7c1a1c72494a3b23c6eb25ea2d0faa8d1b8251c16e6c0d57f681ac46529352a2d88bceaae74d682e7c088b8e14f78f05ccac0405cc29fd5321c2cda3cac36f706529aa3403017b0291699c9aab78849f7e80b2533b53f6daf9f5f0a56df12b1c3eece9177e82013e95c24c7ea440b4ae613841c4deb0db5b886a030a78ba19fb42cccc01623c991e542034b80cee44de62a013ec05e85a024a11740d5dbdbe79810a4f1ea191b8054fa4789e89881a975c00edfd0689479a1a09e8eb6b74266cbd9d96b2f4dd8de3e321e20e4ec9c4d428d9dc73399823744d4262926408e782fb9eefa2ff1f18ffe50b878dd1496de1c0e70b02a856ab16c68e92ae4102b6e21fdd37c9d37e42a06d6c3f1d768e34f0779810813feb2645ee9b13ce6d07823b2092ce22662bf3ba99751ccc7443281b2afcfdf |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.12 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 008c77a0008ff4d1b0c63d9f3a48838d6b |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* ExReleaseFastMutex
* ObfDereferenceObject
* PsLookupProcessByProcessId
* NtQuerySystemInformation
* RtlInitUnicodeString
* KeSetEvent
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
* MmGetSystemRoutineAddress
* ExAcquireFastMutex
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
* MmUnmapLockedPages
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* PAGE
* INIT
* .upx0
* .reloc
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0d424ae0be3a88ff604021ce1400f0dd",
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "TBS": {
        "MD5": "c0189c338449a42fe8358c2c1fbecc60",
        "SHA1": "b8ac0ee6875594b80ad86a6df6dd1fa3048c187c",
        "SHA256": "a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5",
        "SHA384": "76d3a316a5a106050298418cce3beea16100524723d9e3220b0de51bfb6f1c35a5d4c7cd10b358fef7bf94c3e3562150"
      },
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "TBS": {
        "MD5": "cf1823794dca38d348ac92962c7d5169",
        "SHA1": "b8e9d958543069fdabf0c237726e0c7cc43b5dfe",
        "SHA256": "86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8",
        "SHA384": "50169f7ae27863c5c690fba1e7833c6de342cac8aa6e1abca4da93970425d92468a6e81c255e0fb66146823e5b250fc0"
      },
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0409181b5fd5bb66755343b56f955008",
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "TBS": {
        "MD5": "9359496ca4f021408b9d8923cab8b179",
        "SHA1": "2aed40d7759997830870769be250199fd609e40e",
        "SHA256": "e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65",
        "SHA384": "5cb7e7b4f1dbccd48d10db7e71b6f8c05fcb4bcb0085a6fefcfa0c2148f9a594e59f56ac4304004f3b398e259035c40c"
      },
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0aa125d6d6321b7e41e405da3697c215",
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "TBS": {
        "MD5": "8d26184fc613f89aba1cefb30fce1b53",
        "SHA1": "63a7e376bad5ec2e419d514a403bcf46c8d31d95",
        "SHA256": "56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c",
        "SHA384": "d8c9691fe9dbe182f07b49b07fbb4f589fa7b38b5c4d21f265d3a2e818f4b1bfb39e03faab2ec05bb10333a99914fb8a"
      },
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611cb28a000000000026",
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "TBS": {
        "MD5": "983a0c315a50542362f2bd6a5d71c8d0",
        "SHA1": "8047f476001f5cb16a661d2a3fd0c3576168f5e2",
        "SHA256": "5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83",
        "SHA384": "5f014b60511ddab3247ef0b3c03fe82c622237ba76015e2911d1adc50dc632d56ebd1ee532f3c2b6cbfe68d80a2c91dc"
      },
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2022-05-30 11:28:46 |
| MD5                | [5c9f240e0b83df758993837d18859cbe](https://www.virustotal.com/gui/file/5c9f240e0b83df758993837d18859cbe) |
| SHA1               | [4075de7d7d2169d650c5ccede8251463913511e6](https://www.virustotal.com/gui/file/4075de7d7d2169d650c5ccede8251463913511e6) |
| SHA256             | [b531f0a11ca481d5125c93c977325e135a04058019f939169ce3cdedaddd422d](https://www.virustotal.com/gui/file/b531f0a11ca481d5125c93c977325e135a04058019f939169ce3cdedaddd422d) |
| Authentihash MD5   | [a5419f516e383eaf16a76174b3a8becd](https://www.virustotal.com/gui/search/authentihash%253Aa5419f516e383eaf16a76174b3a8becd) |
| Authentihash SHA1  | [e19e10d97d7ecd4a4376196f7e3dfa2365872867](https://www.virustotal.com/gui/search/authentihash%253Ae19e10d97d7ecd4a4376196f7e3dfa2365872867) |
| Authentihash SHA256| [5a021532f0ac453256526428ccf3518cdba4c6373cc72f340ba208b6c41b3a9e](https://www.virustotal.com/gui/search/authentihash%253A5a021532f0ac453256526428ccf3518cdba4c6373cc72f340ba208b6c41b3a9e) |
| RichPEHeaderHash MD5   | [ffdf660eb1ebf020a1d0a55a90712dfb](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Affdf660eb1ebf020a1d0a55a90712dfb) |
| RichPEHeaderHash SHA1  | [3e905e3d061d0d59de61fcf39c994fcb0ec1bab3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e905e3d061d0d59de61fcf39c994fcb0ec1bab3) |
| RichPEHeaderHash SHA256| [2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b3f99a94b7a7132854be769e27b331419c53989ef42f686d6f5ba09ddefefd6) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5c9f240e0b83df758993837d18859cbe.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 330000004de597a775e3157f7b00000000004d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 9f0782e89bd41cdd96ec55357457478a  |
| ToBeSigned (TBS) SHA1             | 35c2180572baad19019acca1334e6c653699c389 |
| ToBeSigned (TBS) SHA256           | 50814710213afec410f26e573d25267a2e21d3d15f158be8a43a666c9cc6fa08 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2021-09-09 19:15:59 |
| ValidTo                           | 2022-09-01 19:15:59 |
| Signature                         | 1757782e797188079911866d54bd474a2432707984658c549a407e7fb4e5efa2ba72367a02b382d2116d4c4538836ddcd4616fcd231229df1ae5d0da6b3abe499ee5d8b47a7919940f6bbcbe2575018dca65eef4913e3d38410f2cd6cca3082d9ba2c061173cd828635665f76e8f0f685e03da24290b9d2cae7039da974de7b7e85798ba64cbe9ba34e0308c3bd6b4d68e9723fde74274fd3806fe799d04d6a3835f82d4fefc52088ccda4b4c817116f2f5a99445a3e952d78bc27753e65e97c6271c71ac7c9e3439b847e8984ab06a5904d150223f9ca92bbda86c02663c3f4964da5e106619b6eaff2768143cce9e5a8b0b2cba90e82cd87866d9fd6499c6cfbc96529a18b5653d12b54a6c928693a4e3d197ffbfcce7ed71a909b18d09b4345b24bc25eb8dfa1821a9cd0971ffc7d38a26580e2f118c4ac55bf926d0666b72ad7ba6ec20f0b54d694bc3b8a0dbddda27bd64194da085319841d1ebc9dc067ef72ea064a475bea865828b13077bc8e14e2f7544b90f0045f3cd84bcc0d5a80645a6fb65528e4f768ec775bdb0225399f3c81c0b667714676d0949f9ffaddc8549dc45e5ce4345c4ea7dc0aff4ac510f5527ad94a2181edc4b73bcfde813a83d81ca897854c98712346001a12e5d3bf9a45c807f9b3c7d3e0bb99c035ea54ee39e2c9af4147dbea7aabec85b47192b945e083ddf6061afb901e83b11135d24e |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 330000004de597a775e3157f7b00000000004d |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
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
* ExDeleteResourceLite
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
* ExAcquireFastMutex
* MmGetSystemRoutineAddress
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
* MmUnlockPages
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .data
* .pdata
* INIT
* .upx0
* .reloc
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0d424ae0be3a88ff604021ce1400f0dd",
      "Signature": "481cdcb5e99a23bce71ae7200e8e6746fd427251740a2347a3ab92d225c47059be14a0e52781a54d1415190779f0d104c386d93bbdfe4402664ded69a40ff6b870cf62e8f5514a7879367a27b7f3e7529f93a7ed439e7be7b4dd412289fb87a246034efcf4feb76477635f2352698382fa1a53ed90cc8da117730df4f36539704bf39cd67a7bda0cbc3d32d01bcbf561fc75080076bc810ef8c0e15ccfc41172e71b6449d8229a751542f52d323881daf460a2bab452fb5ce06124254fb2dfc929a8734351dabd63d61f5b9bf72e1b4f131df74a0d717e97b7f43f84ebc1e3a349a1facea7bf56cfba597661895f7ea7b48e6778f93698e1cb28da5b87a68a2f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021",
      "TBS": {
        "MD5": "c0189c338449a42fe8358c2c1fbecc60",
        "SHA1": "b8ac0ee6875594b80ad86a6df6dd1fa3048c187c",
        "SHA256": "a43de6baf968a942da017b70769fdb65b3cfb1bbca1f9174da26a7d8aae78ec5",
        "SHA384": "76d3a316a5a106050298418cce3beea16100524723d9e3220b0de51bfb6f1c35a5d4c7cd10b358fef7bf94c3e3562150"
      },
      "ValidFrom": "2021-01-01 00:00:00",
      "ValidTo": "2031-01-06 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Signature": "6a8b477edd819b3441be8cab0c2a07d82780ad3a65ff8064c039d44788740835910a4fa5e612987547bdc39e5d61b3204a3463be9dcb5ed1ad060c89943f8471c2960f8a80faae2b2731d5a37434e47f7eeffd43d8493ad2774e3550deb0e741389d22fe70f59e343a38ed2bb62163100055042797203364fcf94121ea5be8f8a20f85b7bc2b52efd87c1b4048c154c7c5a3a40d597c4cb99780f4378d25bff9ad5a1bc5e1f0bb57249efd238973b27f3a4ca6cffa37da752eba7734e3cee24036584b4317ef7ed61e486d8a7959275d2fa28cac8980333a5e2bf5ab6e7de2adcfe2f880972405fb10dad5a67a344e97d6da961c4fd0a1ad8299fbefdc5ebe10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=CN, L=Shanghai, O=miHoYo Co.,Ltd., OU=OPS, CN=miHoYo Co.,Ltd.",
      "TBS": {
        "MD5": "cf1823794dca38d348ac92962c7d5169",
        "SHA1": "b8e9d958543069fdabf0c237726e0c7cc43b5dfe",
        "SHA256": "86c52427d3191c4568149f56ace950e86fa9f8be719cc06575244c6a9f6513e8",
        "SHA384": "50169f7ae27863c5c690fba1e7833c6de342cac8aa6e1abca4da93970425d92468a6e81c255e0fb66146823e5b250fc0"
      },
      "ValidFrom": "2019-04-04 00:00:00",
      "ValidTo": "2022-04-08 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0409181b5fd5bb66755343b56f955008",
      "Signature": "3eec0d5a24b3f322d115c82c7c252976a81d5d1c2d3a1ac4ef3061d77e0b60fdc33d0fc4af8bfdef2adf205537b0e1f6d192750f51b46ea58e5ae25e24814e10a4ee3f718e630e134badd75f4479f33614068af79c464e5cff90b11b070e9115fbbaafb551c28d24ae24c6c7272aa129281a3a7128023c2e91a3c02511e29c1447a17a6868af9ba75c205cd971b10c8fbba8f8c512689fcf40cb4044a513f0e6640c25084232b2368a2402fe2f727e1cd7494596e8591de9fa74646bb2eb6643dab3b08cd5e90dddf60120ce9931633d081a18b3819b4fc6931006fc0781fa8bdaf98249f7626ea153fa129418852e9291ea686c4432b266a1e718a49a6451ef",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "TBS": {
        "MD5": "9359496ca4f021408b9d8923cab8b179",
        "SHA1": "2aed40d7759997830870769be250199fd609e40e",
        "SHA256": "e767799478f64a34b3f53ff3bb9057fe1768f4ab178041b0dcc0ff1e210cba65",
        "SHA384": "5cb7e7b4f1dbccd48d10db7e71b6f8c05fcb4bcb0085a6fefcfa0c2148f9a594e59f56ac4304004f3b398e259035c40c"
      },
      "ValidFrom": "2013-10-22 12:00:00",
      "ValidTo": "2028-10-22 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "0aa125d6d6321b7e41e405da3697c215",
      "Signature": "719512e951875669cdefddda7caa637ab378cf06374084ef4b84bfcacf0302fdc5a7c30e20422caf77f32b1f0c215a2ab705341d6aae99f827a266bf09aa60df76a43a930ff8b2d1d87c1962e85e82251ec4ba1c7b2c21e2d65b2c1435430468b2db7502e072c798d63c64e51f4810185f8938614d62462487638c91522caf2989e5781fd60b14a580d7124770b375d59385937eb69267fb536189a8f56b96c0f458690d7cc801b1b92875b7996385228c61ca79947e59fc8c0fe36fb50126b66ca5ee875121e458609bba0c2d2b6da2c47ebbc4252b4702087c49ae13b6e17c424228c61856cf4134b6665db6747bf55633222f2236b24ba24a95d8f5a68e52",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Timestamping CA",
      "TBS": {
        "MD5": "8d26184fc613f89aba1cefb30fce1b53",
        "SHA1": "63a7e376bad5ec2e419d514a403bcf46c8d31d95",
        "SHA256": "56b5f0d9db578e3f142921daa387902722a76700375c7e1c4ae0ba004bacaa0c",
        "SHA384": "d8c9691fe9dbe182f07b49b07fbb4f589fa7b38b5c4d21f265d3a2e818f4b1bfb39e03faab2ec05bb10333a99914fb8a"
      },
      "ValidFrom": "2016-01-07 12:00:00",
      "ValidTo": "2031-01-07 12:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "611cb28a000000000026",
      "Signature": "5cf5b22d02ceed01b53512d813f7aa4014c7a15ca08a55ed7e55ea6ac457176fd04722423658efc5ac61c5f62c52ce6ae6c80d85dab334420ea40225182672b92a4ea57e4b16f2a0e40c449ce24d9af474f0f927a6699031c244654348c74869d0fc8409f286140ac22996857f11eb8713176ed3ec6bff1d578ab17b1ea5a07ce9a27a68e5fac6b161d67263fa379163835599f81d614f0c6fa3f7bcb1152acc8d85e31417ef7e49443fb022c0f0acbe2fdbe10c86b0f4585c5a10a94bcdf3448a4652083e0a6210e9459504b78b8d4b074f500db7bbe7fb8ca27878c6c53b7663b2cfe521845a66fce04c79834ecfa8ee700586587cc29cd73ca3ad3c7e76625c87d0ed7cd5c55b1421f4be75a275d2e9e15ad020307841624d6b5e6e1b1710244ad8588775d015d762bbfd185665842561977faad49df4f35d6da031c2e19e02ac3e90c3327ee832903416d08b14cf95accee58c54a265b8bfed186a57073ed3e79a4a2f081a041c49871a8ae61b08a365d81c31c50d9cbab368ddf45076160675fec403e7d13edfdc862e10027e661296534e7af3365879b12042d8963f35be3f8ef2999743f5e40ce13c68728c8d49d75a52b573fb7a35943a61b08482c04885c19732d39b725fa0d2348f7ef0467cf28c7294c707b0d7b5b230b81965f09c8327b0a0abd0a2727e050fb3aeddb95b9b42bcc32663456b86f11d4643edc8",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
      "TBS": {
        "MD5": "983a0c315a50542362f2bd6a5d71c8d0",
        "SHA1": "8047f476001f5cb16a661d2a3fd0c3576168f5e2",
        "SHA256": "5f6a519ed2e35cd0fa1cdfc90f4387162c36287bbf9e4d6648251d99542a9e83",
        "SHA384": "5f014b60511ddab3247ef0b3c03fe82c622237ba76015e2911d1adc50dc632d56ebd1ee532f3c2b6cbfe68d80a2c91dc"
      },
      "ValidFrom": "2011-04-15 19:41:37",
      "ValidTo": "2021-04-15 19:51:37",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Assured ID Code Signing CA",
      "SerialNumber": "053ad4f9ee8438ef1662ab8d599213ba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
