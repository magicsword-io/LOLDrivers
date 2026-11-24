+++

description = ""
title = "d009b5bf-d999-4d0b-a4be-1bcbe1effc15"
weight = 10
displayTitle = "vdk.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vdk.sys ![:inline](/images/twitter_verified.png) 

### Description

A vulnerable kernel driver that can be used to disable Code Integrity
- **UUID**: d009b5bf-d999-4d0b-a4be-1bcbe1effc15
- **Created**: 2026-10-25
- **Author**: Andrea Monzani
- **Acknowledgement**: Andrea Monzani, Davide Netti, Antonio Parata | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b0b671c32576d55a02c712b15f167a51.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "vdk.sys" >}}
### Commands

```
sc.exe create vdk binPath=C:\windows\temp\vdk.sys type=kernel &amp;&amp; sc.exe start vdk
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
<li><a href="https://web.archive.org/web/20160808182709/https://kat.lua.cz/posts/Some_fun_with_vintage_bugs_and_driver_signing_enforcement/">https://web.archive.org/web/20160808182709/https://kat.lua.cz/posts/Some_fun_with_vintage_bugs_and_driver_signing_enforcement/</a></li>
<li><a href="https://doi.org/10.1016/j.cose.2026.105194">https://doi.org/10.1016/j.cose.2026.105194</a></li>
<br>

### CVE

<li><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-21709">CVE-2026-21709</a></li>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | vdk.sys |
| Creation Timestamp           | 2019-12-17 17:04:53 |
| MD5                | [b0b671c32576d55a02c712b15f167a51](https://www.virustotal.com/gui/file/b0b671c32576d55a02c712b15f167a51) |
| SHA1               | [80dad0a6dbbd6e4535abbf5446f61c010e101aba](https://www.virustotal.com/gui/file/80dad0a6dbbd6e4535abbf5446f61c010e101aba) |
| SHA256             | [1ca23e5a2a57522fbca4325eb0cc4c5b4f77610f3557862b7b6548efe2dff26b](https://www.virustotal.com/gui/file/1ca23e5a2a57522fbca4325eb0cc4c5b4f77610f3557862b7b6548efe2dff26b) |
| Authentihash MD5   | [6258cb5a25bb2ea89f1c75d153ce27b2](https://www.virustotal.com/gui/search/authentihash%253A6258cb5a25bb2ea89f1c75d153ce27b2) |
| Authentihash SHA1  | [402d31b93abd526d901ea28a5b427ee7eba17ffd](https://www.virustotal.com/gui/search/authentihash%253A402d31b93abd526d901ea28a5b427ee7eba17ffd) |
| Authentihash SHA256| [3b9499627b7a87dd611a2de18dec33274f438607fddbd31716119997ddbabee2](https://www.virustotal.com/gui/search/authentihash%253A3b9499627b7a87dd611a2de18dec33274f438607fddbd31716119997ddbabee2) |
| RichPEHeaderHash MD5   | [c10b8036d334bd658e94c12437eee642](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac10b8036d334bd658e94c12437eee642) |
| RichPEHeaderHash SHA1  | [ee9df90815469f406b89c9c0a7c70ff2f36dec42](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aee9df90815469f406b89c9c0a7c70ff2f36dec42) |
| RichPEHeaderHash SHA256| [64bbd2c46d2c21ebffaf097433608834626ce923f097f2552646d7b404c2944f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A64bbd2c46d2c21ebffaf097433608834626ce923f097f2552646d7b404c2944f) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b0b671c32576d55a02c712b15f167a51.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 33000000857f83dc2a6ca979b8000000000085
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 85e8c40624a19ac2076dd91f49d8fb53  |
| ToBeSigned (TBS) SHA1             | 621756d2a4e10231e34677a3c0f2a8d1fb0fb7ca |
| ToBeSigned (TBS) SHA256           | 442ba2fb3fc8ab1b1b3c71a45f6ea08ce00cea7eae124ef915d4c17622eb336a |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2019-06-05 18:06:32 |
| ValidTo                           | 2020-06-03 18:06:32 |
| Signature                         | 11f64665e99ee9a3212a8317075cf2122256a6cd5452564366da4b3e890c7a94b167d27a0cb1e962de146f371429f531349fc359cccece5f32fa84cd25231f892e44c4676b5ff4008ce6b3f3d9a2690a956a2a6a9e982ba8ebd4256971437156136a25b2e5184e11550aecb83f5ec8ae5467e866d6bbf44b9e8642c8bd5e316a4a494f676aa15eefad41893dd0a7187c881fa235b45f1a0696a8ad2d5c1531eed442d7281290b84f976f9ca241027378c241157a326739b2e8305adbfcef5005f5ccec402c1ab03d6e28c36987ae0d07cd12e41a348098d846f57c3225dbfed0c1b809ad311770854d368d150ee7767676c39a3d148f05cf7c2dcea5f1f7c6f2 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 33000000857f83dc2a6ca979b8000000000085 |
| Version                           | 3 |
###### Certificate 610baac1000000000009
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a569061297e8e824767dbc3184a69bea  |
| ToBeSigned (TBS) SHA1             | adbb26a587a8f44b4fccaecb306f980d1c55a150 |
| ToBeSigned (TBS) SHA256           | cec1afd0e310c55c1dcc601ab8e172917706aa32fb5eaf826813547fdf02dd46 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012 |
| ValidFrom                         | 2012-04-18 23:48:38 |
| ValidTo                           | 2027-04-18 23:58:38 |
| Signature                         | 5a8a67daccd5fd0d264177bf0a4678b4b3de12692b7723c2652f015fd203f461ba509d2e8c3972f36c3e6ab11e766decb7f382dcccbbc56970287366173f54ebee011648c446d91b80ae813a8d0f796d68b09eea2d3f39d3ca387ebd5e7c086e19dcc6c2f438336861e2524783e1000156d2bacb878205310a418b4ee77f5f5fed5fd3392d45eba213bffd1ec298417161165fc80a70257c59693124e471e70abb0417f79f721ec9d2bb1abe3d02fe090cb243b4591a99539396215fe0d6b72601429536ac27fdbef48577683d18bdf4be98882211865216f345ec0397107087a37043713cdbc98603170cf5735bc67de15c64edd7c548d7ed32e2d1aad3cfa7f6574e61f977eb67f288b3de00da038fd08a34373e1dd862b8d2b1f3e12f8b723b81967c6ffcec667672601b24f2a0896d5b6d002eef28dd868705c2b4b9e5be64c22af24a155c98e2c42785ff52e3627e0fb2020bd766c70ab2d33d200414503259830a7d9bed5a38120152ba2f5e20728e4af1fde771028c3be107bec973f4dd47d8b4efb4a4b330b9893e76cab90098567eabea8ab8a5d038ab6977130b142fe9aa411ff7babd3a2b348aee0aab63e663f788248e200d2b3b9de3c24952ac9f1f0e393b5dd46e506ae67d523aaa7c3315290d265e0158a74ea93d7a846f743f609fe4324f3600af6d71d33ea646655f8174f1fec171da4ca0415a82ddf11f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610baac1000000000009 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitializeBitMap
* RtlClearAllBits
* RtlFindClearBits
* RtlClearBits
* RtlSetBits
* RtlAreBitsClear
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* __C_specific_handler
* DbgPrintEx
* KeInitializeEvent
* KeClearEvent
* KeSetEvent
* KeWaitForSingleObject
* KeAcquireSpinLockAtDpcLevel
* KeReleaseSpinLockFromDpcLevel
* ExQueryDepthSList
* ExpInterlockedPopEntrySList
* ExpInterlockedPushEntrySList
* ExInitializeNPagedLookasideList
* ExDeleteNPagedLookasideList
* IofCompleteRequest
* RtlInitializeGenericTableAvl
* RtlInsertElementGenericTableAvl
* RtlDeleteElementGenericTableAvl
* RtlLookupElementGenericTableAvl
* RtlEnumerateGenericTableAvl
* RtlEnumerateGenericTableLikeADirectory
* RtlGetElementGenericTableAvl
* RtlNumberGenericTableElementsAvl
* PsGetCurrentProcessId
* PsGetCurrentThreadId
* RtlInitUnicodeString
* PsCreateSystemThread
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ZwClose
* ZwCreateDirectoryObject
* ZwMakeTemporaryObject
* IoGetConfigurationInformation
* swprintf
* RtlQueryRegistryValues
* RtlGetVersion
* ExInterlockedInsertTailList
* MmProbeAndLockPages
* MmUnlockPages
* MmGetSystemRoutineAddress
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* PsGetVersion
* IoAllocateMdl
* IoFreeMdl
* IoGetDeviceObjectPointer
* IoGetDevicePropertyData
* ZwLoadDriver
* ZwCreateKey
* ZwOpenKey
* ZwSetValueKey
* IoGetLowerDeviceObject
* RtlImageNtHeader
* RtlImageDirectoryEntryToData
* KeFlushEntireTb
* IoSetPartitionInformation
* IoReadPartitionTableEx
* IoSetPartitionInformationEx
* RtlUnicodeStringToAnsiString
* KeWaitForMultipleObjects
* ZwQueryInformationFile
* IoAcquireVpbSpinLock
* IoReleaseVpbSpinLock
* RtlInitAnsiString
* RtlAnsiStringToUnicodeString
* RtlFreeUnicodeString
* RtlCompareMemory
* ZwCreateFile
* ZwSetInformationFile
* ZwReadFile
* ZwWriteFile
* KeSetPriorityThread
* ExInterlockedRemoveHeadList
* PsTerminateSystemThread
* IoEnumerateDeviceObjectList
* _snwprintf
* KeBugCheckEx

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
* .rsrc
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "33000000857f83dc2a6ca979b8000000000085",
      "Signature": "11f64665e99ee9a3212a8317075cf2122256a6cd5452564366da4b3e890c7a94b167d27a0cb1e962de146f371429f531349fc359cccece5f32fa84cd25231f892e44c4676b5ff4008ce6b3f3d9a2690a956a2a6a9e982ba8ebd4256971437156136a25b2e5184e11550aecb83f5ec8ae5467e866d6bbf44b9e8642c8bd5e316a4a494f676aa15eefad41893dd0a7187c881fa235b45f1a0696a8ad2d5c1531eed442d7281290b84f976f9ca241027378c241157a326739b2e8305adbfcef5005f5ccec402c1ab03d6e28c36987ae0d07cd12e41a348098d846f57c3225dbfed0c1b809ad311770854d368d150ee7767676c39a3d148f05cf7c2dcea5f1f7c6f2",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "85e8c40624a19ac2076dd91f49d8fb53",
        "SHA1": "621756d2a4e10231e34677a3c0f2a8d1fb0fb7ca",
        "SHA256": "442ba2fb3fc8ab1b1b3c71a45f6ea08ce00cea7eae124ef915d4c17622eb336a",
        "SHA384": "19b80fb83482cdb42c94c2eabac29e4db7777988905aab348bd7ed62e325d2ea1f4c80df0d7275abcb2b67585cfc7c36"
      },
      "ValidFrom": "2019-06-05 18:06:32",
      "ValidTo": "2020-06-03 18:06:32",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "610baac1000000000009",
      "Signature": "5a8a67daccd5fd0d264177bf0a4678b4b3de12692b7723c2652f015fd203f461ba509d2e8c3972f36c3e6ab11e766decb7f382dcccbbc56970287366173f54ebee011648c446d91b80ae813a8d0f796d68b09eea2d3f39d3ca387ebd5e7c086e19dcc6c2f438336861e2524783e1000156d2bacb878205310a418b4ee77f5f5fed5fd3392d45eba213bffd1ec298417161165fc80a70257c59693124e471e70abb0417f79f721ec9d2bb1abe3d02fe090cb243b4591a99539396215fe0d6b72601429536ac27fdbef48577683d18bdf4be98882211865216f345ec0397107087a37043713cdbc98603170cf5735bc67de15c64edd7c548d7ed32e2d1aad3cfa7f6574e61f977eb67f288b3de00da038fd08a34373e1dd862b8d2b1f3e12f8b723b81967c6ffcec667672601b24f2a0896d5b6d002eef28dd868705c2b4b9e5be64c22af24a155c98e2c42785ff52e3627e0fb2020bd766c70ab2d33d200414503259830a7d9bed5a38120152ba2f5e20728e4af1fde771028c3be107bec973f4dd47d8b4efb4a4b330b9893e76cab90098567eabea8ab8a5d038ab6977130b142fe9aa411ff7babd3a2b348aee0aab63e663f788248e200d2b3b9de3c24952ac9f1f0e393b5dd46e506ae67d523aaa7c3315290d265e0158a74ea93d7a846f743f609fe4324f3600af6d71d33ea646655f8174f1fec171da4ca0415a82ddf11f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012",
      "TBS": {
        "MD5": "a569061297e8e824767dbc3184a69bea",
        "SHA1": "adbb26a587a8f44b4fccaecb306f980d1c55a150",
        "SHA256": "cec1afd0e310c55c1dcc601ab8e172917706aa32fb5eaf826813547fdf02dd46",
        "SHA384": "e947cac936803f5683196e4ff1b259096073395d0b908522ddce90d57597c9f7b57f7ddcdbe021ba863d843c340da8ba"
      },
      "ValidFrom": "2012-04-18 23:48:38",
      "ValidTo": "2027-04-18 23:58:38",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012",
      "SerialNumber": "33000000857f83dc2a6ca979b8000000000085",
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
| Filename           | vdk.sys |
| Creation Timestamp           | 2025-04-10 15:21:23 |
| MD5                | [411bf69a3b8b498dbad84d2764ea2878](https://www.virustotal.com/gui/file/411bf69a3b8b498dbad84d2764ea2878) |
| SHA1               | [a048fb2a98036248292612b5ffb15cdd8af41c95](https://www.virustotal.com/gui/file/a048fb2a98036248292612b5ffb15cdd8af41c95) |
| SHA256             | [2b5e3d36dcbae483ecbbc29725f21bf17438cd286f2f1c5eeea81502a75e695a](https://www.virustotal.com/gui/file/2b5e3d36dcbae483ecbbc29725f21bf17438cd286f2f1c5eeea81502a75e695a) |
| Authentihash MD5   | [e7fd36b8c455196403998504bda5d2b7](https://www.virustotal.com/gui/search/authentihash%253Ae7fd36b8c455196403998504bda5d2b7) |
| Authentihash SHA1  | [a7374e62e88952069acc986ebab16f3d24b88063](https://www.virustotal.com/gui/search/authentihash%253Aa7374e62e88952069acc986ebab16f3d24b88063) |
| Authentihash SHA256| [093f886ab11212cacdbc5e1eedac657a2d3209987e5fd45c7b164a44fcd63a8b](https://www.virustotal.com/gui/search/authentihash%253A093f886ab11212cacdbc5e1eedac657a2d3209987e5fd45c7b164a44fcd63a8b) |
| RichPEHeaderHash MD5   | [4985e31815cd49a0250a3dd606b84b31](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A4985e31815cd49a0250a3dd606b84b31) |
| RichPEHeaderHash SHA1  | [04c5ce12b928f98d527211be94f5e63ca420aa76](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A04c5ce12b928f98d527211be94f5e63ca420aa76) |
| RichPEHeaderHash SHA256| [716b3c64771df855c3ec5955d7e77dec587df29443f1c6ab76b98514dd9adf27](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A716b3c64771df855c3ec5955d7e77dec587df29443f1c6ab76b98514dd9adf27) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/411bf69a3b8b498dbad84d2764ea2878.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000125f31cb555767340d6000000000125
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 581df130bb04487a6d19bc11b5098119  |
| ToBeSigned (TBS) SHA1             | 900451bd61a1199f8b4994f451af8201a1f40c7b |
| ToBeSigned (TBS) SHA256           | 82efe580f6ea4f2a1f39e1f0eaf14983218c1eccbb5d7c80b421501bd4a05a90 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2025-02-20 20:08:09 |
| ValidTo                           | 2026-02-18 20:08:09 |
| Signature                         | 65d17fbf1de2b60cfc46b9d9945a9c84c28a9bac84abe3f49280bca6ff239461c1ba338bfc578d94c884e783881036e134bfd12b52e916281b220f6d34b8ca017fd2880da3b76f90303f497eb18ceebd711083097fee149c5ed15e3b7b4d20ecccb93798c03c462f0039f11b260167512ffd103e20b7b306603f07c1f68940a7074b648a650271c2cbf1dda3e5ba29028c027373faaf255d2af35a86fe539dc5ab7134a4994d5994b4ba7f189bd428778554f9e6402ba8c2cc832bc9fc64d5f6058c2fb6c28ce11798762addd0d567d724e7727b9c3253ea7be34f357ff32c8bb91e8eb198d858118254ceed218f47e94482e8a15f7e095f98c36986f7fa06eb |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000125f31cb555767340d6000000000125 |
| Version                           | 3 |
###### Certificate 610baac1000000000009
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | a569061297e8e824767dbc3184a69bea  |
| ToBeSigned (TBS) SHA1             | adbb26a587a8f44b4fccaecb306f980d1c55a150 |
| ToBeSigned (TBS) SHA256           | cec1afd0e310c55c1dcc601ab8e172917706aa32fb5eaf826813547fdf02dd46 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012 |
| ValidFrom                         | 2012-04-18 23:48:38 |
| ValidTo                           | 2027-04-18 23:58:38 |
| Signature                         | 5a8a67daccd5fd0d264177bf0a4678b4b3de12692b7723c2652f015fd203f461ba509d2e8c3972f36c3e6ab11e766decb7f382dcccbbc56970287366173f54ebee011648c446d91b80ae813a8d0f796d68b09eea2d3f39d3ca387ebd5e7c086e19dcc6c2f438336861e2524783e1000156d2bacb878205310a418b4ee77f5f5fed5fd3392d45eba213bffd1ec298417161165fc80a70257c59693124e471e70abb0417f79f721ec9d2bb1abe3d02fe090cb243b4591a99539396215fe0d6b72601429536ac27fdbef48577683d18bdf4be98882211865216f345ec0397107087a37043713cdbc98603170cf5735bc67de15c64edd7c548d7ed32e2d1aad3cfa7f6574e61f977eb67f288b3de00da038fd08a34373e1dd862b8d2b1f3e12f8b723b81967c6ffcec667672601b24f2a0896d5b6d002eef28dd868705c2b4b9e5be64c22af24a155c98e2c42785ff52e3627e0fb2020bd766c70ab2d33d200414503259830a7d9bed5a38120152ba2f5e20728e4af1fde771028c3be107bec973f4dd47d8b4efb4a4b330b9893e76cab90098567eabea8ab8a5d038ab6977130b142fe9aa411ff7babd3a2b348aee0aab63e663f788248e200d2b3b9de3c24952ac9f1f0e393b5dd46e506ae67d523aaa7c3315290d265e0158a74ea93d7a846f743f609fe4324f3600af6d71d33ea646655f8174f1fec171da4ca0415a82ddf11f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610baac1000000000009 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitializeBitMap
* RtlClearAllBits
* RtlFindClearBits
* RtlClearBits
* RtlSetBits
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* ExFreePoolWithTag
* __C_specific_handler
* DbgPrintEx
* KeGetCurrentIrql
* KeInitializeEvent
* KeClearEvent
* KeSetEvent
* KeWaitForSingleObject
* KeAcquireSpinLockAtDpcLevel
* KeReleaseSpinLockFromDpcLevel
* ExQueryDepthSList
* ExpInterlockedPopEntrySList
* ExpInterlockedPushEntrySList
* ExInitializeNPagedLookasideList
* ExDeleteNPagedLookasideList
* IofCompleteRequest
* RtlInitializeGenericTableAvl
* RtlInsertElementGenericTableAvl
* RtlDeleteElementGenericTableAvl
* RtlLookupElementGenericTableAvl
* RtlEnumerateGenericTableAvl
* RtlEnumerateGenericTableLikeADirectory
* RtlGetElementGenericTableAvl
* RtlNumberGenericTableElementsAvl
* PsGetCurrentProcessId
* PsGetCurrentThreadId
* RtlInitUnicodeString
* PsCreateSystemThread
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ZwClose
* ZwCreateDirectoryObject
* ZwMakeTemporaryObject
* IoGetConfigurationInformation
* swprintf
* RtlQueryRegistryValues
* RtlGetVersion
* ExInterlockedInsertTailList
* MmProbeAndLockPages
* MmUnlockPages
* MmGetSystemRoutineAddress
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* PsGetVersion
* IoAllocateMdl
* IoFreeMdl
* IoGetDeviceObjectPointer
* IoGetDevicePropertyData
* ZwLoadDriver
* ZwCreateKey
* ZwOpenKey
* ZwSetValueKey
* IoGetLowerDeviceObject
* RtlImageNtHeader
* RtlImageDirectoryEntryToData
* KeFlushEntireTb
* IoReadPartitionTableEx
* IoSetPartitionInformationEx
* RtlUnicodeStringToAnsiString
* KeWaitForMultipleObjects
* ZwQueryInformationFile
* IoAcquireVpbSpinLock
* IoReleaseVpbSpinLock
* RtlInitAnsiString
* RtlAnsiStringToUnicodeString
* RtlFreeUnicodeString
* RtlCompareMemory
* ZwCreateFile
* ZwSetInformationFile
* ZwReadFile
* ZwWriteFile
* KeSetPriorityThread
* ExInterlockedRemoveHeadList
* PsTerminateSystemThread
* IoEnumerateDeviceObjectList
* _snwprintf
* KeBugCheckEx

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
* .rsrc
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "33000000857f83dc2a6ca979b8000000000085",
      "Signature": "11f64665e99ee9a3212a8317075cf2122256a6cd5452564366da4b3e890c7a94b167d27a0cb1e962de146f371429f531349fc359cccece5f32fa84cd25231f892e44c4676b5ff4008ce6b3f3d9a2690a956a2a6a9e982ba8ebd4256971437156136a25b2e5184e11550aecb83f5ec8ae5467e866d6bbf44b9e8642c8bd5e316a4a494f676aa15eefad41893dd0a7187c881fa235b45f1a0696a8ad2d5c1531eed442d7281290b84f976f9ca241027378c241157a326739b2e8305adbfcef5005f5ccec402c1ab03d6e28c36987ae0d07cd12e41a348098d846f57c3225dbfed0c1b809ad311770854d368d150ee7767676c39a3d148f05cf7c2dcea5f1f7c6f2",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "85e8c40624a19ac2076dd91f49d8fb53",
        "SHA1": "621756d2a4e10231e34677a3c0f2a8d1fb0fb7ca",
        "SHA256": "442ba2fb3fc8ab1b1b3c71a45f6ea08ce00cea7eae124ef915d4c17622eb336a",
        "SHA384": "19b80fb83482cdb42c94c2eabac29e4db7777988905aab348bd7ed62e325d2ea1f4c80df0d7275abcb2b67585cfc7c36"
      },
      "ValidFrom": "2019-06-05 18:06:32",
      "ValidTo": "2020-06-03 18:06:32",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "610baac1000000000009",
      "Signature": "5a8a67daccd5fd0d264177bf0a4678b4b3de12692b7723c2652f015fd203f461ba509d2e8c3972f36c3e6ab11e766decb7f382dcccbbc56970287366173f54ebee011648c446d91b80ae813a8d0f796d68b09eea2d3f39d3ca387ebd5e7c086e19dcc6c2f438336861e2524783e1000156d2bacb878205310a418b4ee77f5f5fed5fd3392d45eba213bffd1ec298417161165fc80a70257c59693124e471e70abb0417f79f721ec9d2bb1abe3d02fe090cb243b4591a99539396215fe0d6b72601429536ac27fdbef48577683d18bdf4be98882211865216f345ec0397107087a37043713cdbc98603170cf5735bc67de15c64edd7c548d7ed32e2d1aad3cfa7f6574e61f977eb67f288b3de00da038fd08a34373e1dd862b8d2b1f3e12f8b723b81967c6ffcec667672601b24f2a0896d5b6d002eef28dd868705c2b4b9e5be64c22af24a155c98e2c42785ff52e3627e0fb2020bd766c70ab2d33d200414503259830a7d9bed5a38120152ba2f5e20728e4af1fde771028c3be107bec973f4dd47d8b4efb4a4b330b9893e76cab90098567eabea8ab8a5d038ab6977130b142fe9aa411ff7babd3a2b348aee0aab63e663f788248e200d2b3b9de3c24952ac9f1f0e393b5dd46e506ae67d523aaa7c3315290d265e0158a74ea93d7a846f743f609fe4324f3600af6d71d33ea646655f8174f1fec171da4ca0415a82ddf11f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012",
      "TBS": {
        "MD5": "a569061297e8e824767dbc3184a69bea",
        "SHA1": "adbb26a587a8f44b4fccaecb306f980d1c55a150",
        "SHA256": "cec1afd0e310c55c1dcc601ab8e172917706aa32fb5eaf826813547fdf02dd46",
        "SHA384": "e947cac936803f5683196e4ff1b259096073395d0b908522ddce90d57597c9f7b57f7ddcdbe021ba863d843c340da8ba"
      },
      "ValidFrom": "2012-04-18 23:48:38",
      "ValidTo": "2027-04-18 23:58:38",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012",
      "SerialNumber": "33000000857f83dc2a6ca979b8000000000085",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/d009b5bf-d999-4d0b-a4be-1bcbe1effc15.yaml)

*last_updated:* 2026-10-27

{{< /column >}}
{{< /block >}}
