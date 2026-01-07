+++

description = ""
title = "7f80bb6e-bbf6-46dd-b77d-ecef24f1c2cd"
weight = 10
displayTitle = "ksapi.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ksapi.sys ![:inline](/images/twitter_verified.png) 

### Description

Driver can be used to load unsigned drivers
- **UUID**: 7f80bb6e-bbf6-46dd-b77d-ecef24f1c2cd
- **Created**: 2025-09-18
- **Author**: Michael Haag

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6d5fbbb446b119cb151c97b8e16be822.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create ksapi.sys binPath=C:\windows\temp\ksapi.sys type=kernel &amp;&amp; sc.exe start ksapi.sys
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |



### Detections


{{< block "grid-3" >}}
{{< column >}}
#### YARA 🏹
{{< details "Expand" >}}

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/yara-rules_vuln_drivers_strict.yar" "Exact Match" >}}{{< tip >}}with header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/other/yara-rules_vuln_drivers.yar" "Threat Hunting" >}}{{< tip >}}without header and size limitation{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/other/yara-rules_vuln_drivers_strict_renamed.yar" "Renamed" >}}{{< tip >}}for renamed driver files{{< /tip >}} 


{{< /details >}}
{{< /column >}}



{{< column >}}

#### Sigma 🛡️
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sigma/driver_load_win_vuln_drivers_names.yml" "Names" >}}{{< tip >}}detects loading using name only{{< /tip >}} 


{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sigma/driver_load_win_vuln_drivers.yml" "Hashes" >}}{{< tip >}}detects loading using hashes only{{< /tip >}} 

{{< /details >}}

{{< /column >}}


{{< column "mb-2" >}}

#### Sysmon 🔎
{{< details "Expand" >}}
{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sysmon/sysmon_config_vulnerable_hashes_block.xml" "Block" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< button "https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sysmon/sysmon_config_vulnerable_hashes.xml" "Alert" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< /details >}}

{{< /column >}}
{{< /block >}}


### Resources
<br>
<li><a href="https://github.com/BlackSnufkin/BYOVD">https://github.com/BlackSnufkin/BYOVD</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | 26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e |
| Creation Timestamp           | 2017-12-06 04:14:31 |
| MD5                | [6d5fbbb446b119cb151c97b8e16be822](https://www.virustotal.com/gui/file/6d5fbbb446b119cb151c97b8e16be822) |
| SHA1               | [38ce6a9e00b059c1710b728af9454a3e9f45e579](https://www.virustotal.com/gui/file/38ce6a9e00b059c1710b728af9454a3e9f45e579) |
| SHA256             | [26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e](https://www.virustotal.com/gui/file/26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e) |
| Authentihash MD5   | [03ff5165bc71e59c3001152f36628e99](https://www.virustotal.com/gui/search/authentihash%253A03ff5165bc71e59c3001152f36628e99) |
| Authentihash SHA1  | [21f62d2144377d024519b7ea663f692d639fd941](https://www.virustotal.com/gui/search/authentihash%253A21f62d2144377d024519b7ea663f692d639fd941) |
| Authentihash SHA256| [b57caf226aaf1ee53a3e98e2f2ed40837bfa7a889b2914796f03ead147f219a6](https://www.virustotal.com/gui/search/authentihash%253Ab57caf226aaf1ee53a3e98e2f2ed40837bfa7a889b2914796f03ead147f219a6) |
| RichPEHeaderHash MD5   | [f69b0c5ca938ccf37baa4e68f96ff94b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af69b0c5ca938ccf37baa4e68f96ff94b) |
| RichPEHeaderHash SHA1  | [be093c08439526aeafb63750d4adb5e6891f967c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Abe093c08439526aeafb63750d4adb5e6891f967c) |
| RichPEHeaderHash SHA256| [2c074caf50e9b7073c2bbef7a4f988b0ed4cc0304d021c08d57656b6b725f55b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c074caf50e9b7073c2bbef7a4f988b0ed4cc0304d021c08d57656b6b725f55b) |
| Company           | Kingsoft Corporation |
| Description       | Kingsoft KSAPI Module |
| Product           | Kingsoft Antivirus Security System |
| OriginalFilename  | ksapi.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6d5fbbb446b119cb151c97b8e16be822.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 7e93ebfb7cc64e59ea4b9a77d406fc3b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d0785ad36e427c92b19f6826ab1e8020  |
| ToBeSigned (TBS) SHA1             | 365b7a9c21bd9373e49052c3e7b3e4646ddd4d43 |
| ToBeSigned (TBS) SHA256           | c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff |
| Subject                           | CN=Symantec Time Stamping Services CA , G2,O=Symantec Corporation,C=US |
| ValidFrom                         | 2012-12-21 00:00:00 |
| ValidTo                           | 2020-12-30 23:59:59 |
| Signature                         | 03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 7e93ebfb7cc64e59ea4b9a77d406fc3b |
| Version                           | 3 |
###### Certificate 0ecff438c8febf356e04d86a981b1a50
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e9d38360b914c8863f6cba3ee58764d3  |
| ToBeSigned (TBS) SHA1             | 4cba8eae47b6bf76f20b3504b98b8f062694a89b |
| ToBeSigned (TBS) SHA256           | 88901d86a4cc1f1bb193d08e1fb63d27452e63f83e228c657ab1a92e4ade3976 |
| Subject                           | CN=Symantec Time Stamping Services Signer , G4,O=Symantec Corporation,C=US |
| ValidFrom                         | 2012-10-18 00:00:00 |
| ValidTo                           | 2020-12-29 23:59:59 |
| Signature                         | 783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0ecff438c8febf356e04d86a981b1a50 |
| Version                           | 3 |
###### Certificate 4c6d7b5ea289c274426434e65b417aba
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 926f275e20569cb88069ecd4cc0a94bf  |
| ToBeSigned (TBS) SHA1             | 5d767ae1c6d051b4872bb020faed9b867b8b589c |
| ToBeSigned (TBS) SHA256           | 79f52876b273ad0c7ee45c5d7298651797f9f5eb37d5916f7f79a9b404373e4e |
| Subject                           | CN=Beijing Kingsoft Security software Co.,Ltd,OU=IT,O=Beijing Kingsoft Security software Co.,Ltd,L=Beijing,ST=Beijing,C=CN |
| ValidFrom                         | 2017-02-17 00:00:00 |
| ValidTo                           | 2019-03-19 23:59:59 |
| Signature                         | 5a222f1e7c7756188ea9151ce28f7b5b4c76b7c28b9ca26d72402a9c67d9f78eb038cd3297c996274010620ac7fd78c5f21f482a40a2af528625a170c2a52745a0e37203842aac97f3df29d1cc6862472d30c48acde8fec98ca70562c37b86d5ab869f2c336a30f4339cce0a1ef8cfab21daad78aaa4541175ad473742f4228df3531e178ba7abad162cecde2de20aaf9de7058b8bc696d490a386c9d2be0608a0d821e44d7920486484aa72005b349b9fa985fb62c38e802fb3153087cdd77bc9e9cd70b9eedf8a83c75038256cd0c4c26ece2d3708ffce053bccfdb325ba5c187f73f79d5721f0a5356e6cf37f5c3ec9868b1c0ce718f15bfd8c3bc64b2ca0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 4c6d7b5ea289c274426434e65b417aba |
| Version                           | 3 |
###### Certificate 611993e400000000001c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 78a717e082dcc1cda3458d917e677d14  |
| ToBeSigned (TBS) SHA1             | 4a872e0e51f9b304469cd1dedb496ee9b8b983a4 |
| ToBeSigned (TBS) SHA256           | 317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8 |
| Subject                           | CN=VeriSign Class 3 Public Primary Certification Authority , G5,OU=(c) 2006 VeriSign, Inc. , For authorized use only,OU=VeriSign Trust Network,O=VeriSign, Inc.,C=US |
| ValidFrom                         | 2011-02-22 19:25:17 |
| ValidTo                           | 2021-02-22 19:35:17 |
| Signature                         | 812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 611993e400000000001c |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | CN=VeriSign Class 3 Code Signing 2010 CA,OU=Terms of use at https://www.verisign.com/rpa (c)10,OU=VeriSign Trust Network,O=VeriSign, Inc.,C=US |
| ValidFrom                         | 2010-02-08 00:00:00 |
| ValidTo                           | 2020-02-07 23:59:59 |
| Signature                         | 5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 5200e5aa2556fc1a86ed96c9d44b33c7 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* MmGetSystemRoutineAddress
* DbgPrint
* RtlInitUnicodeString
* IoDeleteDevice
* IoFreeMdl
* SeReleaseSubjectContext
* SeCaptureSubjectContext
* IofCompleteRequest
* MmProbeAndLockPages
* MmUnlockPages
* IoCreateSymbolicLink
* IoCreateDevice
* SeTokenIsAdmin
* IoAllocateMdl
* IoDeleteSymbolicLink
* ZwDeleteKey
* IoFileObjectType
* ZwQueryValueKey
* ZwUnmapViewOfSection
* ExAllocatePool
* ZwEnumerateKey
* IoGetCurrentProcess
* ExEventObjectType
* ZwQueryKey
* ExAllocatePoolWithTag
* ProbeForRead
* MmCreateSection
* ZwOpenKey
* NtClose
* KeClearEvent
* ZwEnumerateValueKey
* ZwClose
* ZwCreateKey
* ExFreePoolWithTag
* MmMapViewOfSection
* IoGetBaseFileSystemDeviceObject
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* _wcsnicmp
* IoFreeIrp
* IoGetRelatedDeviceObject
* KeSetEvent
* ProbeForWrite
* IoAllocateIrp
* IoCreateFile
* KeInitializeEvent
* ZwDeleteValueKey
* ZwSetValueKey
* ObfDereferenceObject
* ObInsertObject
* ExAllocatePoolWithQuotaTag
* ObCreateObject
* ZwOpenSymbolicLinkObject
* IoGetDeviceObjectPointer
* IoGetDeviceAttachmentBaseRef
* KeBugCheckEx
* IoCreateFileSpecifyDeviceObjectHint
* SeDeleteAccessState
* ZwOpenFile
* IoReleaseVpbSpinLock
* IoAcquireVpbSpinLock
* ZwQuerySymbolicLinkObject
* SeCreateAccessState
* wcsncpy
* IoGetFileObjectGenericMapping
* PsGetVersion
* ObfReferenceObject
* MmIsAddressValid
* ObOpenObjectByPointer
* _strnicmp
* PsProcessType
* ZwDuplicateObject
* ZwOpenProcess
* PsGetCurrentProcessId
* ZwSetInformationObject
* KeStackAttachProcess
* PsLookupProcessByProcessId
* ZwQuerySystemInformation
* RtlEqualUnicodeString
* KeUnstackDetachProcess
* ZwSetInformationFile
* ObQueryNameString
* ZwWaitForSingleObject
* PsCreateSystemThread
* ExInitializeNPagedLookasideList
* ExpInterlockedPushEntrySList
* ExpInterlockedPopEntrySList
* MmUserProbeAddress
* ExQueryDepthSList
* ExDeleteNPagedLookasideList
* ZwTerminateProcess
* RtlAnsiStringToUnicodeString
* ZwReadFile
* ZwMapViewOfSection
* ZwCreateSection
* RtlImageNtHeader
* SeDeleteObjectAuditAlarm
* ExGetPreviousMode
* __C_specific_handler
* __chkstk

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .data
* .pdata
* PAGE
* INIT
* .rsrc
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=Symantec Time Stamping Services CA , G2,O=Symantec Corporation,C=US",
      "TBS": {
        "MD5": "d0785ad36e427c92b19f6826ab1e8020",
        "SHA1": "365b7a9c21bd9373e49052c3e7b3e4646ddd4d43",
        "SHA256": "c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff",
        "SHA384": "eab4fe5ef90e0de4a6aa3a27769a5e879f588df5e4785aa4104debd1f81e19ea56d33e3a16e5facf99f68b5d8e3d287b"
      },
      "ValidFrom": "2012-12-21 00:00:00",
      "ValidTo": "2020-12-30 23:59:59",
      "Version": 3
    },
    {
      "CertificateType": "Intermediate",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=Symantec Time Stamping Services Signer , G4,O=Symantec Corporation,C=US",
      "TBS": {
        "MD5": "e9d38360b914c8863f6cba3ee58764d3",
        "SHA1": "4cba8eae47b6bf76f20b3504b98b8f062694a89b",
        "SHA256": "88901d86a4cc1f1bb193d08e1fb63d27452e63f83e228c657ab1a92e4ade3976",
        "SHA384": "e9f2a75334a9e336c5a4712eadee88d0374b0fdc273262f4e65c9040ad2793067cc076696db5279a478773485e285652"
      },
      "ValidFrom": "2012-10-18 00:00:00",
      "ValidTo": "2020-12-29 23:59:59",
      "Version": 3
    },
    {
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "4c6d7b5ea289c274426434e65b417aba",
      "Signature": "5a222f1e7c7756188ea9151ce28f7b5b4c76b7c28b9ca26d72402a9c67d9f78eb038cd3297c996274010620ac7fd78c5f21f482a40a2af528625a170c2a52745a0e37203842aac97f3df29d1cc6862472d30c48acde8fec98ca70562c37b86d5ab869f2c336a30f4339cce0a1ef8cfab21daad78aaa4541175ad473742f4228df3531e178ba7abad162cecde2de20aaf9de7058b8bc696d490a386c9d2be0608a0d821e44d7920486484aa72005b349b9fa985fb62c38e802fb3153087cdd77bc9e9cd70b9eedf8a83c75038256cd0c4c26ece2d3708ffce053bccfdb325ba5c187f73f79d5721f0a5356e6cf37f5c3ec9868b1c0ce718f15bfd8c3bc64b2ca0",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=Beijing Kingsoft Security software Co.,Ltd,OU=IT,O=Beijing Kingsoft Security software Co.,Ltd,L=Beijing,ST=Beijing,C=CN",
      "TBS": {
        "MD5": "926f275e20569cb88069ecd4cc0a94bf",
        "SHA1": "5d767ae1c6d051b4872bb020faed9b867b8b589c",
        "SHA256": "79f52876b273ad0c7ee45c5d7298651797f9f5eb37d5916f7f79a9b404373e4e",
        "SHA384": "ad0c57d8fced327ff5b5c6ab55a473e77229368cf866c39ca7a58222e3f3a0883bd39c86182d026c7c30c7baa14d9802"
      },
      "ValidFrom": "2017-02-17 00:00:00",
      "ValidTo": "2019-03-19 23:59:59",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "611993e400000000001c",
      "Signature": "812a82168c34672be503eb347b8ca2a3508af45586f11e8c8eae7dee0319ce72951848ad6211fd20fd3f4706015ae2e06f8c152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d076bcd86a8e26580a8e215e2b2be23056aba0cf347934daca48c077939c061123a050d89a3ec9f578984fbecca7c47661491d8b60f195de6b84aacbc47c8714396e63220a5dc7786fd3ce38b71db7b9b03fcb71d3264eb1652a043a3fa2ead59924e7cc7f233424838513a7c38c71b242228401e1a461f17db18f7f027356cb863d9cdb9645d2ba55eefc629b4f2c7f821cc04ba57fd01b6abc667f9e7d3997ff4f522fa72f5fdff3a1c423aa1f98018a5ee8d1cd4669e4501feaaeefffb178f30f7f1cd29c59decb5d549003d85b8cbbb933a276a49c030ae66c9f723283276f9a48356c848ce5a96aaa0cc0cc47fb48e97af6de35427c39f86c0d6e473089705dbd054625e0348c2d59f7fa7668cd09db04fd4d3985f4b7ac97fb22952d01280c70f54b61e67cdc6a06c110384d34875e72afeb03b6e0a3aa66b769905a3f177686133144706fc537f52bd92145c4a246a678caf8d90aad0f679211b93267cc3ce1ebd883892ae45c6196a4950b305f8ae59378a6a250394b1598150e8ba8380b72335f476b9671d5918ad208d94",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=VeriSign Class 3 Public Primary Certification Authority , G5,OU=(c) 2006 VeriSign, Inc. , For authorized use only,OU=VeriSign Trust Network,O=VeriSign, Inc.,C=US",
      "TBS": {
        "MD5": "78a717e082dcc1cda3458d917e677d14",
        "SHA1": "4a872e0e51f9b304469cd1dedb496ee9b8b983a4",
        "SHA256": "317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8",
        "SHA384": "b71052da4eb9157c8c1a5d7f55df19d69b9128598b72fcca608e5b7cc7d64c43c5504b9c86355a6dc22ee40c88cc385c"
      },
      "ValidFrom": "2011-02-22 19:25:17",
      "ValidTo": "2021-02-22 19:35:17",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=VeriSign Class 3 Code Signing 2010 CA,OU=Terms of use at https://www.verisign.com/rpa (c)10,OU=VeriSign Trust Network,O=VeriSign, Inc.,C=US",
      "TBS": {
        "MD5": "b30c31a572b0409383ed3fbe17e56e81",
        "SHA1": "4843a82ed3b1f2bfbee9671960e1940c942f688d",
        "SHA256": "03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9",
        "SHA384": "bbda8407c4f9fc4e54d772f1c7fb9d30bc97e1f97ecd51c443063d1fa0644e266328781776cd5c44896c457c75f4d7da"
      },
      "ValidFrom": "2010-02-08 00:00:00",
      "ValidTo": "2020-02-07 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "CN=Thawte Timestamping CA,OU=Thawte Certification,O=Thawte,L=Durbanville,ST=Western Cape,C=ZA",
      "SerialNumber": "4c6d7b5ea289c274426434e65b417aba",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/7f80bb6e-bbf6-46dd-b77d-ecef24f1c2cd.yaml)

*last_updated:* 2026-01-07

{{< /column >}}
{{< /block >}}
