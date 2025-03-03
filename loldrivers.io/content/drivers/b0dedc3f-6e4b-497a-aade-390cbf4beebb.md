+++

description = ""
title = "b0dedc3f-6e4b-497a-aade-390cbf4beebb"
weight = 10
displayTitle = "GtcKmdfBs.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# GtcKmdfBs.sys ![:inline](/images/twitter_verified.png)  ![:inline](/images/elmo.gif) 

### Description

The Carbon Black Threat Analysis Unit (TAU) discovered 34 unique vulnerable drivers (237 file hashes) accepting firmware access. Six allow kernel memory access. All give full control of the devices to non-admin users. By exploiting the vulnerable drivers, an attacker without the system privilege may erase/alter firmware, and/or elevate privileges. As of the time of writing in October 2023, the filenames of the vulnerable drivers have not been made public until now.
- **UUID**: b0dedc3f-6e4b-497a-aade-390cbf4beebb
- **Created**: 2023-11-02
- **Author**: Takahiro Haruyama
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e4ea7ebfa142d20a92fbe468a77eafa6.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create GtcKmdfBssys binPath= C:\windows\temp\GtcKmdfBssys.sys type=kernel &amp;&amp; sc.exe start GtcKmdfBssys
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
<li><a href="https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html">https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2021-02-22 23:31:41 |
| MD5                | [e4ea7ebfa142d20a92fbe468a77eafa6](https://www.virustotal.com/gui/file/e4ea7ebfa142d20a92fbe468a77eafa6) |
| SHA1               | [31529d0e73f7fbfbe8c28367466c404c0e3e1d5a](https://www.virustotal.com/gui/file/31529d0e73f7fbfbe8c28367466c404c0e3e1d5a) |
| SHA256             | [0abca92512fc98fe6c2e7d0a33935686fc3acbd0a4c68b51f4a70ece828c0664](https://www.virustotal.com/gui/file/0abca92512fc98fe6c2e7d0a33935686fc3acbd0a4c68b51f4a70ece828c0664) |
| Authentihash MD5   | [dfc36c92d6e0de7f4f181f421812d103](https://www.virustotal.com/gui/search/authentihash%253Adfc36c92d6e0de7f4f181f421812d103) |
| Authentihash SHA1  | [9792ae85f09261a18cfc30a68d2dae36cebd3163](https://www.virustotal.com/gui/search/authentihash%253A9792ae85f09261a18cfc30a68d2dae36cebd3163) |
| Authentihash SHA256| [5d8a10b966e30ee6a696ecc6809936411be7ff672593998693c6b1a58baf0e42](https://www.virustotal.com/gui/search/authentihash%253A5d8a10b966e30ee6a696ecc6809936411be7ff672593998693c6b1a58baf0e42) |
| RichPEHeaderHash MD5   | [ab91c31bf25b2b22cc46d71ce6d549dc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aab91c31bf25b2b22cc46d71ce6d549dc) |
| RichPEHeaderHash SHA1  | [f7354f413084e5ec85ff07e4a994760cad35efa3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Af7354f413084e5ec85ff07e4a994760cad35efa3) |
| RichPEHeaderHash SHA256| [6b417e304c4534d60ab3a4c65cb90f3f908c4f072509567a8bc3ead1583d3ce2](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A6b417e304c4534d60ab3a4c65cb90f3f908c4f072509567a8bc3ead1583d3ce2) |
| Company           | Getac Technology Corporation |
| Description       | Getac System Service Provider |
| Product           | Getac System Service Provider |
| OriginalFilename  | GtcKmdfBs.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e4ea7ebfa142d20a92fbe468a77eafa6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 191a32cb759c97b8cfac118dd5127f49
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 788b61bd26da89253179e3de2cdb527f  |
| ToBeSigned (TBS) SHA1             | 7d06f16e7bf21bce4f71c2cb7a3e74351451bf69 |
| ToBeSigned (TBS) SHA256           | b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19 |
| Subject                           | C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2 |
| ValidFrom                         | 2014-03-04 00:00:00 |
| ValidTo                           | 2024-03-03 23:59:59 |
| Signature                         | 3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 191a32cb759c97b8cfac118dd5127f49 |
| Version                           | 3 |
###### Certificate 3ace4ace02076b0bd6bb6ed06cbb540e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ebe3c04dee2bdd919e2ac4735ec46780  |
| ToBeSigned (TBS) SHA1             | c99e6b965d1da2c16d701a22fcbae0ab5f7d0836 |
| ToBeSigned (TBS) SHA256           | b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f |
| Subject                           | ??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp. |
| ValidFrom                         | 2018-05-15 00:00:00 |
| ValidTo                           | 2021-05-13 23:59:59 |
| Signature                         | c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3ace4ace02076b0bd6bb6ed06cbb540e |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* cng.sys
* ntoskrnl.exe
* WppRecorder.sys
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* BCryptSetProperty
* BCryptCloseAlgorithmProvider
* BCryptDecrypt
* BCryptOpenAlgorithmProvider
* BCryptDestroyKey
* BCryptImportKey
* BCryptGetProperty
* MmUnmapIoSpace
* IoWMIRegistrationControl
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* RtlCopyUnicodeString
* MmMapIoSpace
* _vsnwprintf
* IoWriteErrorLogEntry
* IoAllocateErrorLogEntry
* DbgPrintEx
* WppAutoLogStart
* WppAutoLogStop
* imp_WppRecorderReplay
* WppAutoLogTrace
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass
* WdfVersionBindClass

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
      "IsCertificateAuthority": true,
      "SerialNumber": "191a32cb759c97b8cfac118dd5127f49",
      "Signature": "3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "TBS": {
        "MD5": "788b61bd26da89253179e3de2cdb527f",
        "SHA1": "7d06f16e7bf21bce4f71c2cb7a3e74351451bf69",
        "SHA256": "b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19",
        "SHA384": "2955e28cb7ec0ea9730b499a0f189f9621eceb02591a9486b583f12bb845885a30d6a871826318a167cc5f06b274e58c"
      },
      "ValidFrom": "2014-03-04 00:00:00",
      "ValidTo": "2024-03-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
      "Signature": "c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp.",
      "TBS": {
        "MD5": "ebe3c04dee2bdd919e2ac4735ec46780",
        "SHA1": "c99e6b965d1da2c16d701a22fcbae0ab5f7d0836",
        "SHA256": "b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f",
        "SHA384": "67c38f21e27542536331784edc6de9d71e84ce69b06e5bc8c0ef03ef7de181e7192fd63f754111d3c6b66ce51a661c17"
      },
      "ValidFrom": "2018-05-15 00:00:00",
      "ValidTo": "2021-05-13 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
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
| Creation Timestamp           | 2019-09-26 20:08:13 |
| MD5                | [449bb1c656fa30de7702f17e35b11cd3](https://www.virustotal.com/gui/file/449bb1c656fa30de7702f17e35b11cd3) |
| SHA1               | [273634ac170d1a6abd32e0db597376a6f62eb59e](https://www.virustotal.com/gui/file/273634ac170d1a6abd32e0db597376a6f62eb59e) |
| SHA256             | [4b465faf013929edf2f605c8cd1ac7a278ddc9a536c4c34096965e6852cbfb51](https://www.virustotal.com/gui/file/4b465faf013929edf2f605c8cd1ac7a278ddc9a536c4c34096965e6852cbfb51) |
| Authentihash MD5   | [297e5b42f20370c97d9d0ae19a1335ff](https://www.virustotal.com/gui/search/authentihash%253A297e5b42f20370c97d9d0ae19a1335ff) |
| Authentihash SHA1  | [6d3a6ace2ba6ceb28fbec4995fc3f206054609fc](https://www.virustotal.com/gui/search/authentihash%253A6d3a6ace2ba6ceb28fbec4995fc3f206054609fc) |
| Authentihash SHA256| [cf63f518c9e45fe87d336c87938eb587049602707f1ed16d605f8521f88e4a96](https://www.virustotal.com/gui/search/authentihash%253Acf63f518c9e45fe87d336c87938eb587049602707f1ed16d605f8521f88e4a96) |
| RichPEHeaderHash MD5   | [617bcd4ff070340b124b41d0af0830ae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A617bcd4ff070340b124b41d0af0830ae) |
| RichPEHeaderHash SHA1  | [fe26b24a5dd2ae13dc8f934a29f4bfd8ed242739](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Afe26b24a5dd2ae13dc8f934a29f4bfd8ed242739) |
| RichPEHeaderHash SHA256| [c935e200cf50f432b092791b7e3c1e5e1f279d5b16bc0bd2d31718e51435c53b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac935e200cf50f432b092791b7e3c1e5e1f279d5b16bc0bd2d31718e51435c53b) |
| Company           | Getac Technology Corporation |
| Description       | Getac System Service Provider |
| Product           | Getac System Service Provider |
| OriginalFilename  | GtcKmdfBs.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/449bb1c656fa30de7702f17e35b11cd3.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 7e93ebfb7cc64e59ea4b9a77d406fc3b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d0785ad36e427c92b19f6826ab1e8020  |
| ToBeSigned (TBS) SHA1             | 365b7a9c21bd9373e49052c3e7b3e4646ddd4d43 |
| ToBeSigned (TBS) SHA256           | c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff |
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2 |
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
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4 |
| ValidFrom                         | 2012-10-18 00:00:00 |
| ValidTo                           | 2020-12-29 23:59:59 |
| Signature                         | 783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0ecff438c8febf356e04d86a981b1a50 |
| Version                           | 3 |
###### Certificate 191a32cb759c97b8cfac118dd5127f49
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 788b61bd26da89253179e3de2cdb527f  |
| ToBeSigned (TBS) SHA1             | 7d06f16e7bf21bce4f71c2cb7a3e74351451bf69 |
| ToBeSigned (TBS) SHA256           | b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19 |
| Subject                           | C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2 |
| ValidFrom                         | 2014-03-04 00:00:00 |
| ValidTo                           | 2024-03-03 23:59:59 |
| Signature                         | 3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 191a32cb759c97b8cfac118dd5127f49 |
| Version                           | 3 |
###### Certificate 3ace4ace02076b0bd6bb6ed06cbb540e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ebe3c04dee2bdd919e2ac4735ec46780  |
| ToBeSigned (TBS) SHA1             | c99e6b965d1da2c16d701a22fcbae0ab5f7d0836 |
| ToBeSigned (TBS) SHA256           | b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f |
| Subject                           | ??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp. |
| ValidFrom                         | 2018-05-15 00:00:00 |
| ValidTo                           | 2021-05-13 23:59:59 |
| Signature                         | c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3ace4ace02076b0bd6bb6ed06cbb540e |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* cng.sys
* ntoskrnl.exe
* WppRecorder.sys
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* BCryptDecrypt
* BCryptSetProperty
* BCryptDestroyKey
* BCryptOpenAlgorithmProvider
* BCryptGetProperty
* BCryptCloseAlgorithmProvider
* BCryptImportKey
* MmUnmapIoSpace
* MmMapIoSpace
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* IoWMIRegistrationControl
* _vsnwprintf
* IoWriteErrorLogEntry
* IoAllocateErrorLogEntry
* RtlCopyUnicodeString
* WppAutoLogTrace
* WppAutoLogStop
* WppAutoLogStart
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass
* WdfVersionBindClass

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
      "IsCertificateAuthority": true,
      "SerialNumber": "191a32cb759c97b8cfac118dd5127f49",
      "Signature": "3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "TBS": {
        "MD5": "788b61bd26da89253179e3de2cdb527f",
        "SHA1": "7d06f16e7bf21bce4f71c2cb7a3e74351451bf69",
        "SHA256": "b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19",
        "SHA384": "2955e28cb7ec0ea9730b499a0f189f9621eceb02591a9486b583f12bb845885a30d6a871826318a167cc5f06b274e58c"
      },
      "ValidFrom": "2014-03-04 00:00:00",
      "ValidTo": "2024-03-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
      "Signature": "c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp.",
      "TBS": {
        "MD5": "ebe3c04dee2bdd919e2ac4735ec46780",
        "SHA1": "c99e6b965d1da2c16d701a22fcbae0ab5f7d0836",
        "SHA256": "b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f",
        "SHA384": "67c38f21e27542536331784edc6de9d71e84ce69b06e5bc8c0ef03ef7de181e7192fd63f754111d3c6b66ce51a661c17"
      },
      "ValidFrom": "2018-05-15 00:00:00",
      "ValidTo": "2021-05-13 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
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
| Creation Timestamp           | 2019-07-09 01:12:34 |
| MD5                | [4ec08e0bcdf3e880e7f5a7d78a73440c](https://www.virustotal.com/gui/file/4ec08e0bcdf3e880e7f5a7d78a73440c) |
| SHA1               | [a22c111045b4358f8279190e50851c443534fc24](https://www.virustotal.com/gui/file/a22c111045b4358f8279190e50851c443534fc24) |
| SHA256             | [e6023b8fd2ce4ad2f3005a53aa160772e43fe58da8e467bd05ab71f3335fb822](https://www.virustotal.com/gui/file/e6023b8fd2ce4ad2f3005a53aa160772e43fe58da8e467bd05ab71f3335fb822) |
| Authentihash MD5   | [2981c28ff4148a7b1ecb4ed28e389319](https://www.virustotal.com/gui/search/authentihash%253A2981c28ff4148a7b1ecb4ed28e389319) |
| Authentihash SHA1  | [571a9735893053c2540bf40d353094b5576464af](https://www.virustotal.com/gui/search/authentihash%253A571a9735893053c2540bf40d353094b5576464af) |
| Authentihash SHA256| [1eff553cab0e6db50aa18e1ea10fbc9349b7529c938df4bed580f037cddd1309](https://www.virustotal.com/gui/search/authentihash%253A1eff553cab0e6db50aa18e1ea10fbc9349b7529c938df4bed580f037cddd1309) |
| RichPEHeaderHash MD5   | [b24be74d1225b5f991e3e124a533eabf](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab24be74d1225b5f991e3e124a533eabf) |
| RichPEHeaderHash SHA1  | [5eded17830b30b2018723541845d5090b48494b8](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A5eded17830b30b2018723541845d5090b48494b8) |
| RichPEHeaderHash SHA256| [033c3293cd3c0095f6b3f8961e09cffe8c7ee0d271796e4c3bbf157d073b8a62](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A033c3293cd3c0095f6b3f8961e09cffe8c7ee0d271796e4c3bbf157d073b8a62) |
| Company           | Getac Technology Corporation |
| Description       | Getac System Service Provider |
| Product           | Getac System Service Provider |
| OriginalFilename  | GtcKmdfBs.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4ec08e0bcdf3e880e7f5a7d78a73440c.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 7e93ebfb7cc64e59ea4b9a77d406fc3b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d0785ad36e427c92b19f6826ab1e8020  |
| ToBeSigned (TBS) SHA1             | 365b7a9c21bd9373e49052c3e7b3e4646ddd4d43 |
| ToBeSigned (TBS) SHA256           | c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff |
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2 |
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
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4 |
| ValidFrom                         | 2012-10-18 00:00:00 |
| ValidTo                           | 2020-12-29 23:59:59 |
| Signature                         | 783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0ecff438c8febf356e04d86a981b1a50 |
| Version                           | 3 |
###### Certificate 191a32cb759c97b8cfac118dd5127f49
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 788b61bd26da89253179e3de2cdb527f  |
| ToBeSigned (TBS) SHA1             | 7d06f16e7bf21bce4f71c2cb7a3e74351451bf69 |
| ToBeSigned (TBS) SHA256           | b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19 |
| Subject                           | C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2 |
| ValidFrom                         | 2014-03-04 00:00:00 |
| ValidTo                           | 2024-03-03 23:59:59 |
| Signature                         | 3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 191a32cb759c97b8cfac118dd5127f49 |
| Version                           | 3 |
###### Certificate 3ace4ace02076b0bd6bb6ed06cbb540e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ebe3c04dee2bdd919e2ac4735ec46780  |
| ToBeSigned (TBS) SHA1             | c99e6b965d1da2c16d701a22fcbae0ab5f7d0836 |
| ToBeSigned (TBS) SHA256           | b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f |
| Subject                           | ??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp. |
| ValidFrom                         | 2018-05-15 00:00:00 |
| ValidTo                           | 2021-05-13 23:59:59 |
| Signature                         | c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3ace4ace02076b0bd6bb6ed06cbb540e |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* cng.sys
* ntoskrnl.exe
* WppRecorder.sys
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* BCryptSetProperty
* BCryptCloseAlgorithmProvider
* BCryptDecrypt
* BCryptOpenAlgorithmProvider
* BCryptDestroyKey
* BCryptImportKey
* BCryptGetProperty
* MmUnmapIoSpace
* IoWMIRegistrationControl
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* MmMapIoSpace
* _vsnwprintf
* IoWriteErrorLogEntry
* IoAllocateErrorLogEntry
* RtlCopyUnicodeString
* WppAutoLogStart
* WppAutoLogStop
* imp_WppRecorderReplay
* WppAutoLogTrace
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass
* WdfVersionBindClass

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
      "IsCertificateAuthority": true,
      "SerialNumber": "191a32cb759c97b8cfac118dd5127f49",
      "Signature": "3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "TBS": {
        "MD5": "788b61bd26da89253179e3de2cdb527f",
        "SHA1": "7d06f16e7bf21bce4f71c2cb7a3e74351451bf69",
        "SHA256": "b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19",
        "SHA384": "2955e28cb7ec0ea9730b499a0f189f9621eceb02591a9486b583f12bb845885a30d6a871826318a167cc5f06b274e58c"
      },
      "ValidFrom": "2014-03-04 00:00:00",
      "ValidTo": "2024-03-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
      "Signature": "c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp.",
      "TBS": {
        "MD5": "ebe3c04dee2bdd919e2ac4735ec46780",
        "SHA1": "c99e6b965d1da2c16d701a22fcbae0ab5f7d0836",
        "SHA256": "b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f",
        "SHA384": "67c38f21e27542536331784edc6de9d71e84ce69b06e5bc8c0ef03ef7de181e7192fd63f754111d3c6b66ce51a661c17"
      },
      "ValidFrom": "2018-05-15 00:00:00",
      "ValidTo": "2021-05-13 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
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
| Creation Timestamp           | 2019-09-26 20:07:44 |
| MD5                | [cc35379f0421b907004a9099611ee2cd](https://www.virustotal.com/gui/file/cc35379f0421b907004a9099611ee2cd) |
| SHA1               | [2e9466d5a814c20403be7c7a5811039ca833bd5d](https://www.virustotal.com/gui/file/2e9466d5a814c20403be7c7a5811039ca833bd5d) |
| SHA256             | [e6d1ee0455068b74cf537388c874acb335382876aa9d74586efb05d6cc362ae5](https://www.virustotal.com/gui/file/e6d1ee0455068b74cf537388c874acb335382876aa9d74586efb05d6cc362ae5) |
| Authentihash MD5   | [f0459065e545f61f3e87d36e23dbf9c5](https://www.virustotal.com/gui/search/authentihash%253Af0459065e545f61f3e87d36e23dbf9c5) |
| Authentihash SHA1  | [578a154d0420b3575d26060061428b2feb793356](https://www.virustotal.com/gui/search/authentihash%253A578a154d0420b3575d26060061428b2feb793356) |
| Authentihash SHA256| [37b0aaf4e3cdc9d4c475a3a08ad2ba1e28e177d7359546c9b0bba14ae73dfed0](https://www.virustotal.com/gui/search/authentihash%253A37b0aaf4e3cdc9d4c475a3a08ad2ba1e28e177d7359546c9b0bba14ae73dfed0) |
| RichPEHeaderHash MD5   | [4d8be868521087c4d27dc5a32db1a2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A4d8be868521087c4d27dc5a32db1a2c7) |
| RichPEHeaderHash SHA1  | [9d42b70ad82f9fda96d93c75447d93847f52b20f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A9d42b70ad82f9fda96d93c75447d93847f52b20f) |
| RichPEHeaderHash SHA256| [aad37d8d39b973c6a0d2cacdb141ba3d2749046c4e9a41e1eaa685b0d248e001](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aaad37d8d39b973c6a0d2cacdb141ba3d2749046c4e9a41e1eaa685b0d248e001) |
| Company           | Getac Technology Corporation |
| Description       | Getac System Service Provider |
| Product           | Getac System Service Provider |
| OriginalFilename  | GtcKmdfBs.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/cc35379f0421b907004a9099611ee2cd.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 7e93ebfb7cc64e59ea4b9a77d406fc3b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d0785ad36e427c92b19f6826ab1e8020  |
| ToBeSigned (TBS) SHA1             | 365b7a9c21bd9373e49052c3e7b3e4646ddd4d43 |
| ToBeSigned (TBS) SHA256           | c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff |
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2 |
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
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4 |
| ValidFrom                         | 2012-10-18 00:00:00 |
| ValidTo                           | 2020-12-29 23:59:59 |
| Signature                         | 783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0ecff438c8febf356e04d86a981b1a50 |
| Version                           | 3 |
###### Certificate 191a32cb759c97b8cfac118dd5127f49
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 788b61bd26da89253179e3de2cdb527f  |
| ToBeSigned (TBS) SHA1             | 7d06f16e7bf21bce4f71c2cb7a3e74351451bf69 |
| ToBeSigned (TBS) SHA256           | b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19 |
| Subject                           | C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2 |
| ValidFrom                         | 2014-03-04 00:00:00 |
| ValidTo                           | 2024-03-03 23:59:59 |
| Signature                         | 3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 191a32cb759c97b8cfac118dd5127f49 |
| Version                           | 3 |
###### Certificate 3ace4ace02076b0bd6bb6ed06cbb540e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ebe3c04dee2bdd919e2ac4735ec46780  |
| ToBeSigned (TBS) SHA1             | c99e6b965d1da2c16d701a22fcbae0ab5f7d0836 |
| ToBeSigned (TBS) SHA256           | b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f |
| Subject                           | ??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp. |
| ValidFrom                         | 2018-05-15 00:00:00 |
| ValidTo                           | 2021-05-13 23:59:59 |
| Signature                         | c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3ace4ace02076b0bd6bb6ed06cbb540e |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* cng.sys
* ntoskrnl.exe
* HAL.dll
* WppRecorder.sys
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* BCryptDestroyKey
* BCryptCloseAlgorithmProvider
* BCryptSetProperty
* BCryptGetProperty
* BCryptOpenAlgorithmProvider
* BCryptDecrypt
* BCryptImportKey
* MmUnmapIoSpace
* MmMapIoSpace
* WRITE_REGISTER_BUFFER_USHORT
* WRITE_REGISTER_BUFFER_UCHAR
* READ_REGISTER_BUFFER_ULONG
* READ_REGISTER_BUFFER_USHORT
* READ_REGISTER_BUFFER_UCHAR
* IoWMIRegistrationControl
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* memset
* memcpy
* RtlCopyUnicodeString
* _vsnwprintf
* IoWriteErrorLogEntry
* IoAllocateErrorLogEntry
* WRITE_REGISTER_BUFFER_ULONG
* READ_PORT_UCHAR
* READ_PORT_USHORT
* READ_PORT_ULONG
* WRITE_PORT_UCHAR
* WRITE_PORT_USHORT
* WRITE_PORT_ULONG
* WppAutoLogStart
* WppAutoLogTrace
* WppAutoLogStop
* WdfVersionBindClass
* WdfVersionUnbind
* WdfVersionBind
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
      "IsCertificateAuthority": true,
      "SerialNumber": "191a32cb759c97b8cfac118dd5127f49",
      "Signature": "3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "TBS": {
        "MD5": "788b61bd26da89253179e3de2cdb527f",
        "SHA1": "7d06f16e7bf21bce4f71c2cb7a3e74351451bf69",
        "SHA256": "b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19",
        "SHA384": "2955e28cb7ec0ea9730b499a0f189f9621eceb02591a9486b583f12bb845885a30d6a871826318a167cc5f06b274e58c"
      },
      "ValidFrom": "2014-03-04 00:00:00",
      "ValidTo": "2024-03-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
      "Signature": "c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp.",
      "TBS": {
        "MD5": "ebe3c04dee2bdd919e2ac4735ec46780",
        "SHA1": "c99e6b965d1da2c16d701a22fcbae0ab5f7d0836",
        "SHA256": "b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f",
        "SHA384": "67c38f21e27542536331784edc6de9d71e84ce69b06e5bc8c0ef03ef7de181e7192fd63f754111d3c6b66ce51a661c17"
      },
      "ValidFrom": "2018-05-15 00:00:00",
      "ValidTo": "2021-05-13 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
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
| Creation Timestamp           | 2019-09-26 20:08:13 |
| MD5                | [9993a2a45c745bb0139bf3e8decd626c](https://www.virustotal.com/gui/file/9993a2a45c745bb0139bf3e8decd626c) |
| SHA1               | [68b97bfaf61294743ba15ef36357cdb8e963b56e](https://www.virustotal.com/gui/file/68b97bfaf61294743ba15ef36357cdb8e963b56e) |
| SHA256             | [edbb23e74562e98b849e5d0eefde3af056ec6e272802a04b61bebd12395754e5](https://www.virustotal.com/gui/file/edbb23e74562e98b849e5d0eefde3af056ec6e272802a04b61bebd12395754e5) |
| Authentihash MD5   | [297e5b42f20370c97d9d0ae19a1335ff](https://www.virustotal.com/gui/search/authentihash%253A297e5b42f20370c97d9d0ae19a1335ff) |
| Authentihash SHA1  | [6d3a6ace2ba6ceb28fbec4995fc3f206054609fc](https://www.virustotal.com/gui/search/authentihash%253A6d3a6ace2ba6ceb28fbec4995fc3f206054609fc) |
| Authentihash SHA256| [cf63f518c9e45fe87d336c87938eb587049602707f1ed16d605f8521f88e4a96](https://www.virustotal.com/gui/search/authentihash%253Acf63f518c9e45fe87d336c87938eb587049602707f1ed16d605f8521f88e4a96) |
| RichPEHeaderHash MD5   | [617bcd4ff070340b124b41d0af0830ae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A617bcd4ff070340b124b41d0af0830ae) |
| RichPEHeaderHash SHA1  | [fe26b24a5dd2ae13dc8f934a29f4bfd8ed242739](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Afe26b24a5dd2ae13dc8f934a29f4bfd8ed242739) |
| RichPEHeaderHash SHA256| [c935e200cf50f432b092791b7e3c1e5e1f279d5b16bc0bd2d31718e51435c53b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac935e200cf50f432b092791b7e3c1e5e1f279d5b16bc0bd2d31718e51435c53b) |
| Company           | Getac Technology Corporation |
| Description       | Getac System Service Provider |
| Product           | Getac System Service Provider |
| OriginalFilename  | GtcKmdfBs.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9993a2a45c745bb0139bf3e8decd626c.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 7e93ebfb7cc64e59ea4b9a77d406fc3b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d0785ad36e427c92b19f6826ab1e8020  |
| ToBeSigned (TBS) SHA1             | 365b7a9c21bd9373e49052c3e7b3e4646ddd4d43 |
| ToBeSigned (TBS) SHA256           | c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff |
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2 |
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
| Subject                           | C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4 |
| ValidFrom                         | 2012-10-18 00:00:00 |
| ValidTo                           | 2020-12-29 23:59:59 |
| Signature                         | 783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0ecff438c8febf356e04d86a981b1a50 |
| Version                           | 3 |
###### Certificate 191a32cb759c97b8cfac118dd5127f49
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 788b61bd26da89253179e3de2cdb527f  |
| ToBeSigned (TBS) SHA1             | 7d06f16e7bf21bce4f71c2cb7a3e74351451bf69 |
| ToBeSigned (TBS) SHA256           | b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19 |
| Subject                           | C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2 |
| ValidFrom                         | 2014-03-04 00:00:00 |
| ValidTo                           | 2024-03-03 23:59:59 |
| Signature                         | 3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 191a32cb759c97b8cfac118dd5127f49 |
| Version                           | 3 |
###### Certificate 3ace4ace02076b0bd6bb6ed06cbb540e
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | ebe3c04dee2bdd919e2ac4735ec46780  |
| ToBeSigned (TBS) SHA1             | c99e6b965d1da2c16d701a22fcbae0ab5f7d0836 |
| ToBeSigned (TBS) SHA256           | b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f |
| Subject                           | ??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp. |
| ValidFrom                         | 2018-05-15 00:00:00 |
| ValidTo                           | 2021-05-13 23:59:59 |
| Signature                         | c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3ace4ace02076b0bd6bb6ed06cbb540e |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* cng.sys
* ntoskrnl.exe
* WppRecorder.sys
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* BCryptDecrypt
* BCryptSetProperty
* BCryptDestroyKey
* BCryptOpenAlgorithmProvider
* BCryptGetProperty
* BCryptCloseAlgorithmProvider
* BCryptImportKey
* MmUnmapIoSpace
* MmMapIoSpace
* MmGetSystemRoutineAddress
* RtlInitUnicodeString
* IoWMIRegistrationControl
* _vsnwprintf
* IoWriteErrorLogEntry
* IoAllocateErrorLogEntry
* RtlCopyUnicodeString
* WppAutoLogTrace
* WppAutoLogStop
* WppAutoLogStart
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass
* WdfVersionBindClass

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
      "IsCertificateAuthority": true,
      "SerialNumber": "191a32cb759c97b8cfac118dd5127f49",
      "Signature": "3f5b19f3fa13d575382a5aee9f5aa04ca91dc5cc94eede15fef5106ea41ba56483541858c40b28a185c34e74e5ff897cfed5ed3cba719f5602268f162a88feb0a32722ce4be2388e00a63a865f9de53ea8de644941744121fd07c88417da1d653082cb264f39d60427a481b14b49c3238b7e02321827b7ab0bf31872b6a4ee67066f38a6588de0f17e5da460c6a8e5505fe0e8bae28f9958b6b5a0a876f1a2f11c8841727e52979b0a36998d50f701eb3ce7f0226ae5358c63368a1ab1d967665f971aefa8209df02fba6cced9948500f158f17dc97c22b5075d02c6e60bbfab9393ff27188e33367e5734f1c3af04c184f156b3e8878336f8d30a31dc6e2c6d",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "TBS": {
        "MD5": "788b61bd26da89253179e3de2cdb527f",
        "SHA1": "7d06f16e7bf21bce4f71c2cb7a3e74351451bf69",
        "SHA256": "b3c925b4048c3f7c444d248a2b101186b57cba39596eb5dce0e17a4ee4b32f19",
        "SHA384": "2955e28cb7ec0ea9730b499a0f189f9621eceb02591a9486b583f12bb845885a30d6a871826318a167cc5f06b274e58c"
      },
      "ValidFrom": "2014-03-04 00:00:00",
      "ValidTo": "2024-03-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
      "Signature": "c6d7c068ee995750afcde9392916cb31b300864a35a41e0eaf4f2da79218c1baf1b5ed4b579470ef8996679aabd86ac8e7562b0b4bb74780ab483fda4c30d0e94ef2f8e117a3a5c0c27630e8c0803feb493b55d686e3ed918faab1bc756a6a7ad1e2516e05f98fc950679f32c60d74f954ee6adcef2ee2dcb5bcdca54732b22317f2d232ff0a81373efbe9c95471b69bb3dd9b0f500d37e9e31addf551ce7f849d8a8c9a67eca7eb6d83ebbcbd2253448f671254866b68f3c23b4529a91696666f3f32a081852045ebb792e8f037acd4eba8559d8d1e6a575072b8b2727f28d698b2291c57f100a9ace0d803f62401e75b572aa73c3c5aeb7d4554bc9814c5e7",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=TW, ??=Taipei, ??=Taipei City, ??=Private Organization, serialNumber=22099532, C=TW, ST=Taipei, L=Taipei City, O=Getac Technology Corp., CN=Getac Technology Corp.",
      "TBS": {
        "MD5": "ebe3c04dee2bdd919e2ac4735ec46780",
        "SHA1": "c99e6b965d1da2c16d701a22fcbae0ab5f7d0836",
        "SHA256": "b82ef870260c5011fb8e9704b0eea6fc65a1fdf2cd05bd898e44a89ff714795f",
        "SHA384": "67c38f21e27542536331784edc6de9d71e84ce69b06e5bc8c0ef03ef7de181e7192fd63f754111d3c6b66ce51a661c17"
      },
      "ValidFrom": "2018-05-15 00:00:00",
      "ValidTo": "2021-05-13 23:59:59",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 Extended Validation Code Signing CA , G2",
      "SerialNumber": "3ace4ace02076b0bd6bb6ed06cbb540e",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/b0dedc3f-6e4b-497a-aade-390cbf4beebb.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
