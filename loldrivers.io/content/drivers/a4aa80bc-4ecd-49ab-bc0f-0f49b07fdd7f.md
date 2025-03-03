+++

description = ""
title = "a4aa80bc-4ecd-49ab-bc0f-0f49b07fdd7f"
weight = 10
displayTitle = "segwindrvx64.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# segwindrvx64.sys ![:inline](/images/twitter_verified.png) 

### Description

segwindrvx64.sys is a vulnerable driver and more information will be added as found.
- **UUID**: a4aa80bc-4ecd-49ab-bc0f-0f49b07fdd7f
- **Created**: 2023-01-09
- **Author**: Michael Haag, Nasreddine Bencherchali
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9cbdb5fb6dc63cb13f10b6333407cbb9.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create segwindrvx64.sys binPath=C:\windows\temp\segwindrvx64.sys     type=kernel &amp;&amp; sc.exe start segwindrvx64.sys
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
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           |  |
| Creation Timestamp           | 2014-03-25 23:49:03 |
| MD5                | [9cbdb5fb6dc63cb13f10b6333407cbb9](https://www.virustotal.com/gui/file/9cbdb5fb6dc63cb13f10b6333407cbb9) |
| SHA1               | [fc62b746e0e726537bf848b48212f46db585af6d](https://www.virustotal.com/gui/file/fc62b746e0e726537bf848b48212f46db585af6d) |
| SHA256             | [0d30c6c4fa0216d0637b4049142bc275814fd674859373bd4af520ce173a1c75](https://www.virustotal.com/gui/file/0d30c6c4fa0216d0637b4049142bc275814fd674859373bd4af520ce173a1c75) |
| Authentihash MD5   | [5751b28d2c87f7016e4271edbdcf6017](https://www.virustotal.com/gui/search/authentihash%253A5751b28d2c87f7016e4271edbdcf6017) |
| Authentihash SHA1  | [4fb10f02d5af8ead68a5fdf101651b2f645a9eae](https://www.virustotal.com/gui/search/authentihash%253A4fb10f02d5af8ead68a5fdf101651b2f645a9eae) |
| Authentihash SHA256| [e1d2d76829640542eabc0c96356675c0a930e4607869de8037daf62f898903b5](https://www.virustotal.com/gui/search/authentihash%253Ae1d2d76829640542eabc0c96356675c0a930e4607869de8037daf62f898903b5) |
| RichPEHeaderHash MD5   | [b8dc0c597ed9fbe3b9c1d1979a5835b1](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab8dc0c597ed9fbe3b9c1d1979a5835b1) |
| RichPEHeaderHash SHA1  | [da0ea2d0cb88aa592c6e7236242e8dae028933d2](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ada0ea2d0cb88aa592c6e7236242e8dae028933d2) |
| RichPEHeaderHash SHA256| [6435bf0541179b78d004077d66f1ae9221f7c4653bd69b0b2c7c5073f08d2e4f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A6435bf0541179b78d004077d66f1ae9221f7c4653bd69b0b2c7c5073f08d2e4f) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9cbdb5fb6dc63cb13f10b6333407cbb9.bin" "Download" >}} 

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
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* ExAllocatePoolWithTag
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapIoSpace
* _vsnprintf
* IofCompleteRequest
* RtlCompareMemory
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* MmMapLockedPagesSpecifyCache
* RtlQueryRegistryValues
* ZwCreateFile
* ExSystemTimeToLocalTime
* ZwClose
* RtlTimeToTimeFields
* ZwWriteFile
* RtlInitAnsiString
* ExAllocatePool
* RtlFreeAnsiString
* RtlCopyString
* RtlEqualString
* MmGetSystemRoutineAddress
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* init
* page
* .rdata
* .data
* .pdata
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
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
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
| Filename           | segwindrvx64.sys |
| Creation Timestamp           | 2015-04-01 03:39:09 |
| MD5                | [4ae55080ec8aed49343e40d08370195c](https://www.virustotal.com/gui/file/4ae55080ec8aed49343e40d08370195c) |
| SHA1               | [d702d88b12233be9413446c445f22fda4a92a1d9](https://www.virustotal.com/gui/file/d702d88b12233be9413446c445f22fda4a92a1d9) |
| SHA256             | [65329dad28e92f4bcc64de15c552b6ef424494028b18875b7dba840053bc0cdd](https://www.virustotal.com/gui/file/65329dad28e92f4bcc64de15c552b6ef424494028b18875b7dba840053bc0cdd) |
| Authentihash MD5   | [bfc8d6405949be17179975d604e62c90](https://www.virustotal.com/gui/search/authentihash%253Abfc8d6405949be17179975d604e62c90) |
| Authentihash SHA1  | [c7d32983805f04c7aac4e9713d203399aaca7acc](https://www.virustotal.com/gui/search/authentihash%253Ac7d32983805f04c7aac4e9713d203399aaca7acc) |
| Authentihash SHA256| [f1f345591efe74fd12e706132939f51963eb39dd0a1db556123c3e850c60fada](https://www.virustotal.com/gui/search/authentihash%253Af1f345591efe74fd12e706132939f51963eb39dd0a1db556123c3e850c60fada) |
| RichPEHeaderHash MD5   | [dc3dfe1fda1d095e5fa3849e71bb1fb6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adc3dfe1fda1d095e5fa3849e71bb1fb6) |
| RichPEHeaderHash SHA1  | [772d5aa7af303c29b3901b79fcca7b061680e29e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A772d5aa7af303c29b3901b79fcca7b061680e29e) |
| RichPEHeaderHash SHA256| [82732fd11bdbc96fa1c3a0b827c338cc56c5c8d8bdae6c6a7a5006b7d611d9c2](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A82732fd11bdbc96fa1c3a0b827c338cc56c5c8d8bdae6c6a7a5006b7d611d9c2) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4ae55080ec8aed49343e40d08370195c.bin" "Download" >}} 

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
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 611993e400000000001c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 78a717e082dcc1cda3458d917e677d14  |
| ToBeSigned (TBS) SHA1             | 4a872e0e51f9b304469cd1dedb496ee9b8b983a4 |
| ToBeSigned (TBS) SHA256           | 317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
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
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* MmMapLockedPagesSpecifyCache
* MmMapIoSpace
* MmUnmapIoSpace
* MmAllocateContiguousMemorySpecifyCache
* MmFreeContiguousMemorySpecifyCache
* IofCompleteRequest
* MmGetPhysicalAddress
* _vsnprintf
* RtlInitUnicodeString
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmGetSystemRoutineAddress
* RtlInitAnsiString
* RtlFreeAnsiString
* ExAllocatePool
* RtlCopyString
* RtlEqualString
* RtlCompareMemory
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlQueryRegistryValues
* RtlTimeToTimeFields
* ExSystemTimeToLocalTime
* ZwCreateFile
* ZwWriteFile
* ZwClose
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* page
* init
* .rdata
* .data
* .pdata
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
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
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
| Filename           | segwindrvx64.sys |
| Creation Timestamp           | 2014-03-18 14:20:01 |
| MD5                | [bdc3b6b83dde7111d5d6b9a2aadf233f](https://www.virustotal.com/gui/file/bdc3b6b83dde7111d5d6b9a2aadf233f) |
| SHA1               | [2ade3347df84d6707f39d9b821890440bcfdb5e9](https://www.virustotal.com/gui/file/2ade3347df84d6707f39d9b821890440bcfdb5e9) |
| SHA256             | [c628cda1ef43defc00af45b79949675a8422490d32b080b3a8bb9434242bdbf2](https://www.virustotal.com/gui/file/c628cda1ef43defc00af45b79949675a8422490d32b080b3a8bb9434242bdbf2) |
| Authentihash MD5   | [9eea185193b6357a2bd97455572b650c](https://www.virustotal.com/gui/search/authentihash%253A9eea185193b6357a2bd97455572b650c) |
| Authentihash SHA1  | [4ac29762ab2ad025a13a1e8cf7af9b7f4c875aac](https://www.virustotal.com/gui/search/authentihash%253A4ac29762ab2ad025a13a1e8cf7af9b7f4c875aac) |
| Authentihash SHA256| [ca213b79336c69128620bc39e6d987c1e605299fb6525344ba1b08b7829197c7](https://www.virustotal.com/gui/search/authentihash%253Aca213b79336c69128620bc39e6d987c1e605299fb6525344ba1b08b7829197c7) |
| RichPEHeaderHash MD5   | [b771c0bd9fe0e428b467b774d1cbc0bf](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab771c0bd9fe0e428b467b774d1cbc0bf) |
| RichPEHeaderHash SHA1  | [93b03b61a7b4b4efd2f85ff40709bdacae9d0a2a](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A93b03b61a7b4b4efd2f85ff40709bdacae9d0a2a) |
| RichPEHeaderHash SHA256| [98f486ee105b32d3e054170a341c20d2874830b8f67bd00bf2479a10ed9497b1](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A98f486ee105b32d3e054170a341c20d2874830b8f67bd00bf2479a10ed9497b1) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/bdc3b6b83dde7111d5d6b9a2aadf233f.bin" "Download" >}} 

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
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* MmMapLockedPagesSpecifyCache
* MmMapIoSpace
* MmUnmapIoSpace
* MmAllocateContiguousMemorySpecifyCache
* MmFreeContiguousMemorySpecifyCache
* IofCompleteRequest
* MmGetPhysicalAddress
* _vsnprintf
* RtlInitUnicodeString
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmGetSystemRoutineAddress
* RtlInitAnsiString
* RtlFreeAnsiString
* ExAllocatePool
* RtlCopyString
* RtlEqualString
* RtlCompareMemory
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlQueryRegistryValues
* RtlTimeToTimeFields
* ExSystemTimeToLocalTime
* ZwCreateFile
* ZwWriteFile
* ZwClose
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* page
* init
* .rdata
* .data
* .pdata
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
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
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
| Creation Timestamp           | 2014-03-18 14:27:12 |
| MD5                | [31a331a88c6280555859455518a95c35](https://www.virustotal.com/gui/file/31a331a88c6280555859455518a95c35) |
| SHA1               | [c3be2bbd9b3f696bc9d51d5973cc00ca059fb172](https://www.virustotal.com/gui/file/c3be2bbd9b3f696bc9d51d5973cc00ca059fb172) |
| SHA256             | [7164aaff86b3b7c588fc7ae7839cc09c5c8c6ae29d1aff5325adaf5bedd7c9f5](https://www.virustotal.com/gui/file/7164aaff86b3b7c588fc7ae7839cc09c5c8c6ae29d1aff5325adaf5bedd7c9f5) |
| Authentihash MD5   | [455be805eef8874daa03b46c0dc8237b](https://www.virustotal.com/gui/search/authentihash%253A455be805eef8874daa03b46c0dc8237b) |
| Authentihash SHA1  | [7ebdf0f226a8e60cc9da39add12f75e17f615b7a](https://www.virustotal.com/gui/search/authentihash%253A7ebdf0f226a8e60cc9da39add12f75e17f615b7a) |
| Authentihash SHA256| [ee8ee16198dd8eec8d5fbb7f98f64bb849b2dfcf652cc102f4cdc63a4551549f](https://www.virustotal.com/gui/search/authentihash%253Aee8ee16198dd8eec8d5fbb7f98f64bb849b2dfcf652cc102f4cdc63a4551549f) |
| RichPEHeaderHash MD5   | [d3ecd8b9995fa87438ee429391c9f76b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad3ecd8b9995fa87438ee429391c9f76b) |
| RichPEHeaderHash SHA1  | [ac66be77e53f64702c8fc8ef219a1ce42794fa58](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aac66be77e53f64702c8fc8ef219a1ce42794fa58) |
| RichPEHeaderHash SHA256| [e663e1327e434c11c041d6a8df33663ce4228f15fffabbf4a18863be02d1bb2b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae663e1327e434c11c041d6a8df33663ce4228f15fffabbf4a18863be02d1bb2b) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/31a331a88c6280555859455518a95c35.bin" "Download" >}} 

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
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* WRITE_REGISTER_ULONG
* WRITE_REGISTER_BUFFER_UCHAR
* MmMapLockedPagesSpecifyCache
* MmMapIoSpace
* MmUnmapIoSpace
* MmAllocateContiguousMemorySpecifyCache
* MmFreeContiguousMemorySpecifyCache
* IofCompleteRequest
* MmGetPhysicalAddress
* _vsnprintf
* memcpy
* memset
* RtlInitUnicodeString
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmGetSystemRoutineAddress
* RtlInitAnsiString
* RtlFreeAnsiString
* WRITE_REGISTER_USHORT
* RtlCopyString
* RtlEqualString
* RtlCompareMemory
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlQueryRegistryValues
* RtlTimeToTimeFields
* KeQuerySystemTime
* ExSystemTimeToLocalTime
* ZwCreateFile
* ZwWriteFile
* ZwClose
* KeTickCount
* KeBugCheckEx
* WRITE_REGISTER_UCHAR
* READ_REGISTER_BUFFER_UCHAR
* READ_REGISTER_ULONG
* READ_REGISTER_USHORT
* ExAllocatePool
* READ_REGISTER_UCHAR
* WRITE_PORT_ULONG
* WRITE_PORT_UCHAR
* READ_PORT_ULONG
* READ_PORT_UCHAR
* KeGetCurrentIrql

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* page
* .text
* init
* .rdata
* .data
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
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
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
| Creation Timestamp           | 2014-09-19 00:42:51 |
| MD5                | [875c44411674b75feb07592aeffa09c1](https://www.virustotal.com/gui/file/875c44411674b75feb07592aeffa09c1) |
| SHA1               | [dc69a6cdf048e2c4a370d4b5cafd717d236374ea](https://www.virustotal.com/gui/file/dc69a6cdf048e2c4a370d4b5cafd717d236374ea) |
| SHA256             | [b9ae1d53a464bc9bb86782ab6c55e2da8804c80a361139a82a6c8eef30fddd7c](https://www.virustotal.com/gui/file/b9ae1d53a464bc9bb86782ab6c55e2da8804c80a361139a82a6c8eef30fddd7c) |
| Authentihash MD5   | [0c6627c22f2d4cedbace35610ef22217](https://www.virustotal.com/gui/search/authentihash%253A0c6627c22f2d4cedbace35610ef22217) |
| Authentihash SHA1  | [287617c248c57c29357d09d46b795690efeb1f7f](https://www.virustotal.com/gui/search/authentihash%253A287617c248c57c29357d09d46b795690efeb1f7f) |
| Authentihash SHA256| [f83465d2c38c20a3854d86c293867de3baae2f90419dbe82405bc9f9dd7bbd8c](https://www.virustotal.com/gui/search/authentihash%253Af83465d2c38c20a3854d86c293867de3baae2f90419dbe82405bc9f9dd7bbd8c) |
| RichPEHeaderHash MD5   | [dc3dfe1fda1d095e5fa3849e71bb1fb6](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Adc3dfe1fda1d095e5fa3849e71bb1fb6) |
| RichPEHeaderHash SHA1  | [772d5aa7af303c29b3901b79fcca7b061680e29e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A772d5aa7af303c29b3901b79fcca7b061680e29e) |
| RichPEHeaderHash SHA256| [82732fd11bdbc96fa1c3a0b827c338cc56c5c8d8bdae6c6a7a5006b7d611d9c2](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A82732fd11bdbc96fa1c3a0b827c338cc56c5c8d8bdae6c6a7a5006b7d611d9c2) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/875c44411674b75feb07592aeffa09c1.bin" "Download" >}} 

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
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 611993e400000000001c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 78a717e082dcc1cda3458d917e677d14  |
| ToBeSigned (TBS) SHA1             | 4a872e0e51f9b304469cd1dedb496ee9b8b983a4 |
| ToBeSigned (TBS) SHA256           | 317fa1d234ebc49040ebc5e8746f8997471496051b185a91bdd9dfbb23fab5f8 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
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
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* MmMapLockedPagesSpecifyCache
* MmMapIoSpace
* MmUnmapIoSpace
* MmAllocateContiguousMemorySpecifyCache
* MmFreeContiguousMemorySpecifyCache
* IofCompleteRequest
* MmGetPhysicalAddress
* _vsnprintf
* RtlInitUnicodeString
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* MmGetSystemRoutineAddress
* RtlInitAnsiString
* RtlFreeAnsiString
* ExAllocatePool
* RtlCopyString
* RtlEqualString
* RtlCompareMemory
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlQueryRegistryValues
* RtlTimeToTimeFields
* ExSystemTimeToLocalTime
* ZwCreateFile
* ZwWriteFile
* ZwClose
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* page
* init
* .rdata
* .data
* .pdata
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
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
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
| Creation Timestamp           | 2013-11-15 00:50:12 |
| MD5                | [dad8f40626ed4702e0e8502562d93d7c](https://www.virustotal.com/gui/file/dad8f40626ed4702e0e8502562d93d7c) |
| SHA1               | [b4f1877156bf3157bff1170ba878848b2f22d2d5](https://www.virustotal.com/gui/file/b4f1877156bf3157bff1170ba878848b2f22d2d5) |
| SHA256             | [38d6d90d543bf6037023c1b1b14212b4fa07731cbbb44bdb17e8faffc12b22e8](https://www.virustotal.com/gui/file/38d6d90d543bf6037023c1b1b14212b4fa07731cbbb44bdb17e8faffc12b22e8) |
| Authentihash MD5   | [0bc06ae681c0c6d57349c70a56da0d6c](https://www.virustotal.com/gui/search/authentihash%253A0bc06ae681c0c6d57349c70a56da0d6c) |
| Authentihash SHA1  | [95c09ff1fdec9fa1739492c047d333fd8124b33b](https://www.virustotal.com/gui/search/authentihash%253A95c09ff1fdec9fa1739492c047d333fd8124b33b) |
| Authentihash SHA256| [61bd9a26c01371d865e681f6354853dc0e27b1064906cd99b15220098be6e88d](https://www.virustotal.com/gui/search/authentihash%253A61bd9a26c01371d865e681f6354853dc0e27b1064906cd99b15220098be6e88d) |
| RichPEHeaderHash MD5   | [11b19e98ecaef1027a2916f67da6a9ee](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A11b19e98ecaef1027a2916f67da6a9ee) |
| RichPEHeaderHash SHA1  | [99dee060fc9d3cd87aee4f8fba92d26f17355497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A99dee060fc9d3cd87aee4f8fba92d26f17355497) |
| RichPEHeaderHash SHA256| [35396200c56c16bfeca125286105155e2126b3b4d30f6159af19cfbe512c5014](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A35396200c56c16bfeca125286105155e2126b3b4d30f6159af19cfbe512c5014) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/dad8f40626ed4702e0e8502562d93d7c.bin" "Download" >}} 

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
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* ExAllocatePoolWithTag
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapIoSpace
* _vsnprintf
* IofCompleteRequest
* RtlCompareMemory
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* MmMapLockedPagesSpecifyCache
* RtlQueryRegistryValues
* ZwCreateFile
* ExSystemTimeToLocalTime
* ZwClose
* RtlTimeToTimeFields
* ZwWriteFile
* MmGetSystemRoutineAddress
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* init
* page
* .rdata
* .data
* .pdata
* INIT
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
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
| Creation Timestamp           | 2013-02-21 22:35:02 |
| MD5                | [f14359ceb3705d77353b244bb795b552](https://www.virustotal.com/gui/file/f14359ceb3705d77353b244bb795b552) |
| SHA1               | [a09334489fb18443c8793cb0395860518193cc3c](https://www.virustotal.com/gui/file/a09334489fb18443c8793cb0395860518193cc3c) |
| SHA256             | [0452a6e8f00bae0b79335c1799a26b2b77d603451f2e6cc3b137ad91996d4dec](https://www.virustotal.com/gui/file/0452a6e8f00bae0b79335c1799a26b2b77d603451f2e6cc3b137ad91996d4dec) |
| Authentihash MD5   | [1845c2eab4e455303c6505335101afb6](https://www.virustotal.com/gui/search/authentihash%253A1845c2eab4e455303c6505335101afb6) |
| Authentihash SHA1  | [5c0bf58978971842776ce4ec33ad6bcdeaeee353](https://www.virustotal.com/gui/search/authentihash%253A5c0bf58978971842776ce4ec33ad6bcdeaeee353) |
| Authentihash SHA256| [b06dad9821beef3442cd9e775228baa56582a3a85c9d178693f3cf236623de17](https://www.virustotal.com/gui/search/authentihash%253Ab06dad9821beef3442cd9e775228baa56582a3a85c9d178693f3cf236623de17) |
| RichPEHeaderHash MD5   | [a6b77c0eb57f1bd34daae338bb41d04d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aa6b77c0eb57f1bd34daae338bb41d04d) |
| RichPEHeaderHash SHA1  | [4754c75aa96693cd9803574f6c98b3d7871d0d9f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A4754c75aa96693cd9803574f6c98b3d7871d0d9f) |
| RichPEHeaderHash SHA256| [2290ea57e29d9e155bcd0a4582b5b9476a2c2e5f4de38f807190b13401e2c4b8](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2290ea57e29d9e155bcd0a4582b5b9476a2c2e5f4de38f807190b13401e2c4b8) |
| Company           | Insyde Software Corp. |
| Description       | SEG Windows Driver x64 |
| Product           | SEG Windows Driver x64 |
| OriginalFilename  | segwindrvx64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f14359ceb3705d77353b244bb795b552.bin" "Download" >}} 

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
###### Certificate 250ce8e030612e9f2b89f7054d7cf8fd
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 918d9eb6a6cd36c531eceb926170a7e1  |
| ToBeSigned (TBS) SHA1             | 0ae95700d65e6f59715aa47048993ca7858e676a |
| ToBeSigned (TBS) SHA256           | 47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5 |
| ValidFrom                         | 2006-11-08 00:00:00 |
| ValidTo                           | 2021-11-07 23:59:59 |
| Signature                         | 1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 250ce8e030612e9f2b89f7054d7cf8fd |
| Version                           | 3 |
###### Certificate 610c120600000000001b
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 53c41bc1164e09e0cd1617a5bf913efd  |
| ToBeSigned (TBS) SHA1             | 93c03aac8951d494ecd5696b1c08658541b18727 |
| ToBeSigned (TBS) SHA256           | 40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b |
| Subject                           | C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority |
| ValidFrom                         | 2006-05-23 17:01:29 |
| ValidTo                           | 2016-05-23 17:11:29 |
| Signature                         | 01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 610c120600000000001b |
| Version                           | 3 |
###### Certificate 0355af7ef9418e476d877eecd9f9e9e2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 768c1a47836a7536fbc50e7be60e65ff  |
| ToBeSigned (TBS) SHA1             | 569a77bd8a095070b13b75bc81cd0422f746daa3 |
| ToBeSigned (TBS) SHA256           | d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369 |
| Subject                           | C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp. |
| ValidFrom                         | 2012-12-28 00:00:00 |
| ValidTo                           | 2016-01-27 23:59:59 |
| Signature                         | 19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0355af7ef9418e476d877eecd9f9e9e2 |
| Version                           | 3 |
###### Certificate 5200e5aa2556fc1a86ed96c9d44b33c7
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | b30c31a572b0409383ed3fbe17e56e81  |
| ToBeSigned (TBS) SHA1             | 4843a82ed3b1f2bfbee9671960e1940c942f688d |
| ToBeSigned (TBS) SHA256           | 03cda47a6e654ed85d932714fc09ce4874600eda29ec6628cfbaeb155cab78c9 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA |
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
* ExAllocatePoolWithTag
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapIoSpace
* _vsnprintf
* IofCompleteRequest
* RtlCompareMemory
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* MmMapLockedPagesSpecifyCache
* RtlQueryRegistryValues
* ZwCreateFile
* ExSystemTimeToLocalTime
* ExAllocatePool
* ZwClose
* RtlTimeToTimeFields
* ZwWriteFile
* KeBugCheckEx

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* init
* page
* .rdata
* .data
* .pdata
* INIT
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "7e93ebfb7cc64e59ea4b9a77d406fc3b",
      "Signature": "03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca86518e979406225966ec7c7376a8321088e41eaddd9573f1d7749872a16065ea6386a2212a35119837eb6",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2",
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
      "IsCertificateAuthority": false,
      "SerialNumber": "0ecff438c8febf356e04d86a981b1a50",
      "Signature": "783bb4912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4356c7c8916c6e9b2dfb2e9dd20c6710fcd9574dcb65cdebd371f4378e678b5cd280420a3aaf14bc48829910e80d111fcdd5c766e4f5e0e4546416e0db0ea389ab13ada097110fc1c79b4807bac69f4fd9cb60c162bf17f5b093d9b5be216ca13816d002e380da8298f2ce1b2f45aa901af159c2c2f491bdb22bbc3fe789451c386b182885df03db451a179332b2e7bb9dc20091371eb6a195bcfe8a530572c89493fb9cf7fc9bf3e226863539abd6974acc51d3c7f92e0c3bc1cd80475",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services Signer , G4",
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
      "IsCertificateAuthority": true,
      "SerialNumber": "250ce8e030612e9f2b89f7054d7cf8fd",
      "Signature": "1302ddf8e88600f25af8f8200c59886207cecef74ef9bb59a198e5e138dd4ebc6618d3adeb18f20dc96d3e4a9420c33cbabd6554c6af44b310ad2c6b3eabd707b6b88163c5f95e2ee52a67cecd330c2ad7895603231fb3bee83a0859b4ec4535f78a5bff66cf50afc66d578d1978b7b9a2d157ea1f9a4bafbac98e127ec6bdff",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign, Inc. , For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority , G5",
      "TBS": {
        "MD5": "918d9eb6a6cd36c531eceb926170a7e1",
        "SHA1": "0ae95700d65e6f59715aa47048993ca7858e676a",
        "SHA256": "47c46e6eaa3780eace3d0d891346cd373359d246b21a957219dbab4c8f37c166",
        "SHA384": "e54017c93ba52f012cc15aeb3bcbce1e90a0006ff8dca231a24fc572926770f63213343f538003407bed3463fa9c4a85"
      },
      "ValidFrom": "2006-11-08 00:00:00",
      "ValidTo": "2021-11-07 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "610c120600000000001b",
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "TBS": {
        "MD5": "53c41bc1164e09e0cd1617a5bf913efd",
        "SHA1": "93c03aac8951d494ecd5696b1c08658541b18727",
        "SHA256": "40bddadac24dc61ca4fb5cab2a2bc5d876bc36808311039a7a3e1a4066f7489b",
        "SHA384": "f51d4e75ba638f7314cd59b8d6d45f3b34d35ce6986e9d205cd6f333e8e8d8e9c91f636e6bc84731b6661673f40963d8"
      },
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Signature": "19cf4cfe8a901a2d50614d496664fcdaaa80098ec50cec3e3f56a3d08a399d96d13046789c8281a1a9bf1054c79351f73e091664da593dcd39ec4ad7077513b01270666042cb743d4cd2387b61067384d5ed20ee0773e7e61fc1a8a750c3882c6e64ad0f8819b91c19c50708510467ee34ac845fb0a68259e90c7dbef65dcc4b75c72fde8d954ef37d53bba6f00a40e1c85deeb81531772b07232f8e8fe791eac42ab152b5e970c008f14bdec7a7e1ac114bae73ae1ba4f3a525a169f37de670a9447f65653426abb77c6a8b7f91c2d5428a63059129ba94818d3f6cceac0e0790ddb23d56f598e0a9083fc8b92a3b100c0dc1729290ba44fb1538ac4cedf926",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=TW, ST=Taiwan, L=Taipei, O=Insyde Software Corp., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Insyde Software Corp.",
      "TBS": {
        "MD5": "768c1a47836a7536fbc50e7be60e65ff",
        "SHA1": "569a77bd8a095070b13b75bc81cd0422f746daa3",
        "SHA256": "d5289c20d1f89ac5000b691627764379d369c68ab7d53425baa8e83f09b5b369",
        "SHA384": "92eb214d60e1c7342eb7b4863dd634d364d80494b4090301e872fba4d2efbec2a799d49f0ac9590f8c61e0fb3b905af3"
      },
      "ValidFrom": "2012-12-28 00:00:00",
      "ValidTo": "2016-01-27 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "5200e5aa2556fc1a86ed96c9d44b33c7",
      "Signature": "5622e634a4c461cb48b901ad56a8640fd98c91c4bbcc0ce5ad7aa0227fdf47384a2d6cd17f711a7cec70a9b1f04fe40f0c53fa155efe749849248581261c911447b04c638cbba134d4c645e80d85267303d0a98c646ddc7192e645056015595139fc58146bfed4a4ed796b080c4172e737220609be23e93f449a1ee9619dccb1905cfc3dd28dac423d6536d4b43d40288f9b10cf2326cc4b20cb901f5d8c4c34ca3cd8e537d66fa520bd34eb26d9ae0de7c59af7a1b42191336f86e858bb257c740e58fe751b633fce317c9b8f1b969ec55376845b9cad91faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
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
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)10, CN=VeriSign Class 3 Code Signing 2010 CA",
      "SerialNumber": "0355af7ef9418e476d877eecd9f9e9e2",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/a4aa80bc-4ecd-49ab-bc0f-0f49b07fdd7f.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
