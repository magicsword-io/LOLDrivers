+++

description = ""
title = "b7bfe661-591a-45be-823d-ac6dae2edeed"
weight = 10
displayTitle = "mtxC9CB.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# mtxC9CB.sys ![:inline](/images/twitter_verified.png) 

### Description

mtxC9CB.sys is a vulnerable kernel driver from the KeServiceDescriptorTable/vulnerable-drivers repository. The driver exposes dangerous kernel primitives to usermode.
- **UUID**: b7bfe661-591a-45be-823d-ac6dae2edeed
- **Created**: 2026-04-17
- **Author**: Michael Haag
- **Acknowledgement**:  | [@rainbowdynamix, @DbgPrint](https://twitter.com/@rainbowdynamix, @DbgPrint)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e0efe6ca3af0eddd2ea34899206dc989.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "mtxC9CB.sys" >}}
### Commands

```
sc.exe create mtxC9CB binPath=C:\windows\temp\mtxC9CB.sys type=kernel &amp;&amp; sc.exe start mtxC9CB
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
<li><a href="https://github.com/magicsword-io/LOLDrivers/issues/325">https://github.com/magicsword-io/LOLDrivers/issues/325</a></li>
<li><a href="https://github.com/KeServiceDescriptorTable/vulnerable-drivers">https://github.com/KeServiceDescriptorTable/vulnerable-drivers</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | mtxC9CB.sys |
| Creation Timestamp           | 2013-05-17 11:17:38 |
| MD5                | [e0efe6ca3af0eddd2ea34899206dc989](https://www.virustotal.com/gui/file/e0efe6ca3af0eddd2ea34899206dc989) |
| SHA1               | [f0f325dc9b15fef3781d01b6b14022a89c68ca46](https://www.virustotal.com/gui/file/f0f325dc9b15fef3781d01b6b14022a89c68ca46) |
| SHA256             | [0414c0d5bb6ddbcc84b3d59ce411acf1ed8b17d17054c6192e0a7594b5146d60](https://www.virustotal.com/gui/file/0414c0d5bb6ddbcc84b3d59ce411acf1ed8b17d17054c6192e0a7594b5146d60) |
| Authentihash MD5   | [b68d529d159b0704137ea1498f00c7ce](https://www.virustotal.com/gui/search/authentihash%253Ab68d529d159b0704137ea1498f00c7ce) |
| Authentihash SHA1  | [a64ee7f9111becdf289f3460de1dd10bd0d739a6](https://www.virustotal.com/gui/search/authentihash%253Aa64ee7f9111becdf289f3460de1dd10bd0d739a6) |
| Authentihash SHA256| [cde6cb8bba989b5e2b197611b96471199e8a0484e895da46e3d3007d3a328151](https://www.virustotal.com/gui/search/authentihash%253Acde6cb8bba989b5e2b197611b96471199e8a0484e895da46e3d3007d3a328151) |
| RichPEHeaderHash MD5   | [87154042676217891333b5fc400110e5](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A87154042676217891333b5fc400110e5) |
| RichPEHeaderHash SHA1  | [8c469857b46f73e737a5c01694adb9be9c4291b0](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8c469857b46f73e737a5c01694adb9be9c4291b0) |
| RichPEHeaderHash SHA256| [79cf4518bde93c25dfe3199203610da6b590aa7bc46887f053d62178bb4c3930](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A79cf4518bde93c25dfe3199203610da6b590aa7bc46887f053d62178bb4c3930) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e0efe6ca3af0eddd2ea34899206dc989.bin" "Download" >}} 

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
###### Certificate 1e972d89426edbed34425009a3bd806d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 997e7a3272a2b0ae17ad19b6863f47ab  |
| ToBeSigned (TBS) SHA1             | 02ed23b839152c86be4c21d379395b65e828e8f0 |
| ToBeSigned (TBS) SHA256           | 098218d4509c8c2da63a1c80cb177a9333be52f17f49e046fc614c2a712e9a95 |
| Subject                           | C=CA, ST=Quebec, L=Dorval, O=Matrox Graphics Inc., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Matrox Graphics Inc. |
| ValidFrom                         | 2013-05-07 00:00:00 |
| ValidTo                           | 2014-05-29 23:59:59 |
| Signature                         | 10c4077601cb89c9a157643e43f9aca3e43f99be76bd57c0f9c6fa6d1a16134fe777390c708a2cb0f8423baa497897c7b486cb46efb6ef41a7e55e9e892a1b9db99920a8fd5f43e2d457fabe424f4b57049bb4c0f5d5db89a42cfdb915d0c642e5b344a73a81f3ac9ccdbaccba0442e88d16d204e5171182b31154969ad528891688f3e68bd42e3a5f0e930c327cf71f1422d00340bc84f742215d01d43ba75c3361bc87e5392b97bec4b99ca9d7a7c2ad92c3f7c0854150ce4a96dd2bc13037edd4f227e0e20a25ad268027546e7734c03025a0bd16a9dd0c56565e5c0e0e9fa4db52cbe7cac8068ff2d87e398a7ce4c5b6439c00fe245817b7d1d45cd0e787 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1e972d89426edbed34425009a3bd806d |
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
* IoCreateSymbolicLink
* ZwOpenSection
* ObReferenceObjectByHandle
* ZwMapViewOfSection
* ObfDereferenceObject
* ZwClose
* ZwUnmapViewOfSection
* IoCreateDevice
* MmUnmapIoSpace
* MmAllocateContiguousMemory
* MmGetPhysicalAddress
* MmFreeContiguousMemory
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* MmMapIoSpace
* IofCompleteRequest
* HalSetBusDataByOffset
* HalGetBusDataByOffset

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
      "CertificateType": "Intermediate",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": false,
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
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": true,
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
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "1e972d89426edbed34425009a3bd806d",
      "Signature": "10c4077601cb89c9a157643e43f9aca3e43f99be76bd57c0f9c6fa6d1a16134fe777390c708a2cb0f8423baa497897c7b486cb46efb6ef41a7e55e9e892a1b9db99920a8fd5f43e2d457fabe424f4b57049bb4c0f5d5db89a42cfdb915d0c642e5b344a73a81f3ac9ccdbaccba0442e88d16d204e5171182b31154969ad528891688f3e68bd42e3a5f0e930c327cf71f1422d00340bc84f742215d01d43ba75c3361bc87e5392b97bec4b99ca9d7a7c2ad92c3f7c0854150ce4a96dd2bc13037edd4f227e0e20a25ad268027546e7734c03025a0bd16a9dd0c56565e5c0e0e9fa4db52cbe7cac8068ff2d87e398a7ce4c5b6439c00fe245817b7d1d45cd0e787",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Dorval, O=Matrox Graphics Inc., OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=Matrox Graphics Inc.",
      "TBS": {
        "MD5": "997e7a3272a2b0ae17ad19b6863f47ab",
        "SHA1": "02ed23b839152c86be4c21d379395b65e828e8f0",
        "SHA256": "098218d4509c8c2da63a1c80cb177a9333be52f17f49e046fc614c2a712e9a95",
        "SHA384": "be03390520e7f29876faac20c1b0e8c1943e14696070c5a3f142ff1000d27732e16f59419b14a01ca0f20e924c157241"
      },
      "ValidFrom": "2013-05-07 00:00:00",
      "ValidTo": "2014-05-29 23:59:59",
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
      "SerialNumber": "1e972d89426edbed34425009a3bd806d",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/b7bfe661-591a-45be-823d-ac6dae2edeed.yaml)

*last_updated:* 2026-04-20

{{< /column >}}
{{< /block >}}
