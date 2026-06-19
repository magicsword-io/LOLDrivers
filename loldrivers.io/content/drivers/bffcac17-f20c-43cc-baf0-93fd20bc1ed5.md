+++

description = ""
title = "bffcac17-f20c-43cc-baf0-93fd20bc1ed5"
weight = 10
displayTitle = "unknown.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# unknown.sys ![:inline](/images/twitter_verified.png) 

### Description

unknown.sys is an unattributed signed kernel driver documented in public UnknownKiller / BlackSnufkin BYOVD research. The public PoCs identify the driver as exposing a process-kill primitive suitable for BYOVD process termination research.
- **UUID**: bffcac17-f20c-43cc-baf0-93fd20bc1ed5
- **Created**: 2026-06-16
- **Author**: Michael Haag
- **Acknowledgement**: BlackSnufkin / lukmannurhikma | [@BlackSnufkin42 / @lukmannurhikma](https://twitter.com/@BlackSnufkin42 / @lukmannurhikma)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4e5136230ec590ce6ef038aac6e72cb2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "unknown.sys" >}}
### Commands

```
sc.exe create unknown binPath=C:\windows\temp\unknown.sys type=kernel &amp;&amp; sc.exe start unknown
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Terminate processes from kernel mode through an unattributed vulnerable driver. | kernel | Windows 10, Windows 11 |



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
<li><a href="https://github.com/BlackSnufkin/BYOVD/tree/main/UnknownKiller">https://github.com/BlackSnufkin/BYOVD/tree/main/UnknownKiller</a></li>
<li><a href="https://github.com/lukmannurhikma/UnknownKiller">https://github.com/lukmannurhikma/UnknownKiller</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | unknown.sys |
| Creation Timestamp           | 2024-11-29 17:15:50 |
| MD5                | [4e5136230ec590ce6ef038aac6e72cb2](https://www.virustotal.com/gui/file/4e5136230ec590ce6ef038aac6e72cb2) |
| SHA1               | [ba914fe77b177b45799403b16dd14765c510a074](https://www.virustotal.com/gui/file/ba914fe77b177b45799403b16dd14765c510a074) |
| SHA256             | [97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091](https://www.virustotal.com/gui/file/97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091) |
| Authentihash MD5   | [793ea731f474590d5542d0df0f1db133](https://www.virustotal.com/gui/search/authentihash%253A793ea731f474590d5542d0df0f1db133) |
| Authentihash SHA1  | [ed88d7f2d05454545272e80a8c6450783a4e6083](https://www.virustotal.com/gui/search/authentihash%253Aed88d7f2d05454545272e80a8c6450783a4e6083) |
| Authentihash SHA256| [0d7099bd4a0714a354cfe36f312d907843bcaaa2a1e3dcf269637f58920b1e47](https://www.virustotal.com/gui/search/authentihash%253A0d7099bd4a0714a354cfe36f312d907843bcaaa2a1e3dcf269637f58920b1e47) |
| RichPEHeaderHash MD5   | [7aeb0c4cf7961d5e9a110c152b975dde](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7aeb0c4cf7961d5e9a110c152b975dde) |
| RichPEHeaderHash SHA1  | [2f65984d2f1c266865faa954b4becd6dc0aefc6f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2f65984d2f1c266865faa954b4becd6dc0aefc6f) |
| RichPEHeaderHash SHA256| [c0e40a6d627e4ab5e7421b2a28abb50b2d1f5b51a0e587fe49487f6191b39983](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac0e40a6d627e4ab5e7421b2a28abb50b2d1f5b51a0e587fe49487f6191b39983) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4e5136230ec590ce6ef038aac6e72cb2.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 77f685fe096792d8605e243ecdcc9f63eaf940b3
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 58c1bd6db58833b50407d01d1bd174e4  |
| ToBeSigned (TBS) SHA1             | 6958f6814b8105d5fd3894b61dec15d1b5a7caf7 |
| ToBeSigned (TBS) SHA256           | 61970b3445e9d357c3270a4c6f976bc7d074e47462e97111a8a0d199b89b313c |
| Subject                           | C=CN, O=Microsoft Windows Hardware Compatibility Publisher, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2025-09-01 16:20:58 |
| ValidTo                           | 2026-09-01 16:20:58 |
| Signature                         | 3046022100c43caac50d639f514a37d188330d15d91cbf2021c4d9b48e0e51fbe37180346e022100a13554245e188623b6ed5e24bd84488341f06f1c432159cdaf51176c91caeb57 |
| SignatureAlgorithmOID             | 1.2.840.10045.4.3.2 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 77f685fe096792d8605e243ecdcc9f63eaf940b3 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* RtlAnsiStringToUnicodeString
* RtlFreeUnicodeString
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* __chkstk
* RtlEqualUnicodeString
* ExAllocatePoolWithTagPriority
* ExFreePoolWithTag
* MmProbeAndLockPages
* MmUnlockPages
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* IoAllocateMdl
* IoFreeMdl
* IoGetCurrentProcess
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ObRegisterCallbacks
* ObUnRegisterCallbacks
* ZwClose
* MmIsAddressValid
* PsGetProcessId
* IoCreateFileSpecifyDeviceObjectHint
* ZwTerminateProcess
* KeStackAttachProcess
* KeUnstackDetachProcess
* PsLookupProcessByProcessId
* ZwDeleteFile
* ZwAllocateVirtualMemory
* ZwFreeVirtualMemory
* ZwWaitForSingleObject
* PsGetProcessWow64Process
* PsGetProcessPeb
* MmCopyVirtualMemory
* ZwProtectVirtualMemory
* RtlCreateUserThread
* ZwQuerySystemInformation
* __C_specific_handler
* PsProcessType

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
* .reloc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "CertificateType": "Intermediate",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": false,
      "SerialNumber": "77f685fe096792d8605e243ecdcc9f63eaf940b3",
      "Signature": "3046022100c43caac50d639f514a37d188330d15d91cbf2021c4d9b48e0e51fbe37180346e022100a13554245e188623b6ed5e24bd84488341f06f1c432159cdaf51176c91caeb57",
      "SignatureAlgorithmOID": "1.2.840.10045.4.3.2",
      "Subject": "C=CN, O=Microsoft Windows Hardware Compatibility Publisher, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "58c1bd6db58833b50407d01d1bd174e4",
        "SHA1": "6958f6814b8105d5fd3894b61dec15d1b5a7caf7",
        "SHA256": "61970b3445e9d357c3270a4c6f976bc7d074e47462e97111a8a0d199b89b313c",
        "SHA384": "948c9bf666bfaa1208a9585c70b89210a0bdf5fc1c9120b2a9940f776a404323ed12d7b5045609ded0939b5b532d6fed"
      },
      "ValidFrom": "2025-09-01 16:20:58",
      "ValidTo": "2026-09-01 16:20:58",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=CN, O=Microsoft Windows Third Party Component CA, CN=Microsoft Windows Third Party Component CA",
      "SerialNumber": "77f685fe096792d8605e243ecdcc9f63eaf940b3",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/bffcac17-f20c-43cc-baf0-93fd20bc1ed5.yaml)

*last_updated:* 2026-06-19

{{< /column >}}
{{< /block >}}
