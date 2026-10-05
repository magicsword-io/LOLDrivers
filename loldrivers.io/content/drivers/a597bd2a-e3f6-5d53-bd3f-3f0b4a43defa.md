+++

description = ""
title = "a597bd2a-e3f6-5d53-bd3f-3f0b4a43defa"
weight = 10
displayTitle = "IoDrv.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# IoDrv.sys ![:inline](/images/twitter_verified.png) 

### Description

IoDrv.sys is a hardware I/O driver with an embedded TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd signature. Beazley Security identified this exact sample, renamed Redacted.sys, in an INC ransomware affiliate intrusion. The accompanying Redacted EDR Blinder reportedly used the driver to modify security-driver code and impair endpoint defenses. The sample contains physical-memory mapping and port-I/O interfaces. The reported EDR-targeting logic belongs to the accompanying executable, not a built-in target list in the driver. Current Windows loading-policy compatibility and the runtime attack were not independently tested.
- **UUID**: a597bd2a-e3f6-5d53-bd3f-3f0b4a43defa
- **Created**: 2026-09-28
- **Author**: Michael Haag
- **Acknowledgement**: Beazley Security DFIR and MXDR teams | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a63d5ed574d0231c958551903c4ddf28.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "IoDrv.sys" >}}


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Abuse a hardware-access driver to impair endpoint defenses. | Administrator privileges to load the driver; access to its device is also required. | Windows |



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
<li><a href="https://labs.beazley.security/articles/an-inc-ransomware-affiliates-byovd-buffet">https://labs.beazley.security/articles/an-inc-ransomware-affiliates-byovd-buffet</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | IoDrv.sys |
| Creation Timestamp           | 2011-09-11 16:00:54 |
| MD5                | [a63d5ed574d0231c958551903c4ddf28](https://www.virustotal.com/gui/file/a63d5ed574d0231c958551903c4ddf28) |
| SHA1               | [844304be902d933f0b335b35bebbe620b6c8d613](https://www.virustotal.com/gui/file/844304be902d933f0b335b35bebbe620b6c8d613) |
| SHA256             | [266d2027a8fc999773c88defd4591d02b8819cf6b07699182319338270b399d2](https://www.virustotal.com/gui/file/266d2027a8fc999773c88defd4591d02b8819cf6b07699182319338270b399d2) |
| Authentihash MD5   | [0eacee5e31837ad90f20db9a8f781aed](https://www.virustotal.com/gui/search/authentihash%253A0eacee5e31837ad90f20db9a8f781aed) |
| Authentihash SHA1  | [99100b871242499156d6360082d240a6fd9fdd4b](https://www.virustotal.com/gui/search/authentihash%253A99100b871242499156d6360082d240a6fd9fdd4b) |
| Authentihash SHA256| [6601964a52268d49def829aacd687faad911be77a3d5240394a4b63967fe4838](https://www.virustotal.com/gui/search/authentihash%253A6601964a52268d49def829aacd687faad911be77a3d5240394a4b63967fe4838) |
| RichPEHeaderHash MD5   | [2b745d90a102a42256774e350aac3080](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2b745d90a102a42256774e350aac3080) |
| RichPEHeaderHash SHA1  | [45768de16e9654a5b21dcc916b5115ef81950791](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A45768de16e9654a5b21dcc916b5115ef81950791) |
| RichPEHeaderHash SHA256| [59089a80084d2dd2efbc48ed53ce8eb6198155fe8552e36c1355c732691963a3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A59089a80084d2dd2efbc48ed53ce8eb6198155fe8552e36c1355c732691963a3) |
| Publisher         | TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a63d5ed574d0231c958551903c4ddf28.bin" "Download" >}} 

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
###### Certificate 232e30bacc6345c699d0fdb676fef270
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 0b469652d1cab99fd65d76fcd8f8520a  |
| ToBeSigned (TBS) SHA1             | 07cdbbbee5c7dbc49dafae04345eb5ea4b7c623b |
| ToBeSigned (TBS) SHA256           | dc86534af67ae1380584d262759d8de67c74d66b4fc17a46fe426d3b8d63c7a4 |
| Subject                           | C=CN, ST=GuangDong, L=ShenZhen, O=TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=TOPSTAR,TEST, CN=TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd |
| ValidFrom                         | 2011-03-09 00:00:00 |
| ValidTo                           | 2013-03-08 23:59:59 |
| Signature                         | 4df99c91be6c4d2471fab892e12d3ef56e74f1717ee5212fd0b6101a8831f8604724b7fc33d3695f0a1a97e341a161971890915042f9267730d9e89ef12d0b557b8666c40df9a6322b9f9a9ae85a536b7612dfcbf42779f03bbeb81e1821af61e89aeca1ea8bb3026ab2ff5d9f12ac6bff15fcb0b9e7752a8fa850fb1b30c29bdf9f288d70f4b4057ca270bfd8f4af6359ef3a8ff817843840df4dc0a487ccd6c83708ec9af8824ddf1e79506bd0aeef8122a579b2dc56d16c536b9fd0ab5b1f5c971d94b1225a6e7c2abea5649758f1800e0519b527e7b4deb8a80b9035dd0380a544db00c6d7dc6024d2c1a7f4a6cbc3265cb90920321aa01959bed37923db |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 232e30bacc6345c699d0fdb676fef270 |
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
* RtlInitUnicodeString
* IoDeleteDevice
* ZwUnmapViewOfSection
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* ZwMapViewOfSection
* ObfDereferenceObject
* IoCreateDevice
* RtlAssert
* ZwOpenSection
* DbgPrint
* KeBugCheckEx
* IoCreateSymbolicLink
* IoDeleteSymbolicLink
* HalTranslateBusAddress

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
      "SerialNumber": "232e30bacc6345c699d0fdb676fef270",
      "Signature": "4df99c91be6c4d2471fab892e12d3ef56e74f1717ee5212fd0b6101a8831f8604724b7fc33d3695f0a1a97e341a161971890915042f9267730d9e89ef12d0b557b8666c40df9a6322b9f9a9ae85a536b7612dfcbf42779f03bbeb81e1821af61e89aeca1ea8bb3026ab2ff5d9f12ac6bff15fcb0b9e7752a8fa850fb1b30c29bdf9f288d70f4b4057ca270bfd8f4af6359ef3a8ff817843840df4dc0a487ccd6c83708ec9af8824ddf1e79506bd0aeef8122a579b2dc56d16c536b9fd0ab5b1f5c971d94b1225a6e7c2abea5649758f1800e0519b527e7b4deb8a80b9035dd0380a544db00c6d7dc6024d2c1a7f4a6cbc3265cb90920321aa01959bed37923db",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CN, ST=GuangDong, L=ShenZhen, O=TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=TOPSTAR,TEST, CN=TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd",
      "TBS": {
        "MD5": "0b469652d1cab99fd65d76fcd8f8520a",
        "SHA1": "07cdbbbee5c7dbc49dafae04345eb5ea4b7c623b",
        "SHA256": "dc86534af67ae1380584d262759d8de67c74d66b4fc17a46fe426d3b8d63c7a4",
        "SHA384": "42bb8121e324e54f66d33519fa8a2a09b673ffca6d5b5ce541269ee94b7a41969b7c3f33b57385602e916f1ae7d49c31"
      },
      "ValidFrom": "2011-03-09 00:00:00",
      "ValidTo": "2013-03-08 23:59:59",
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
      "SerialNumber": "232e30bacc6345c699d0fdb676fef270",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/a597bd2a-e3f6-5d53-bd3f-3f0b4a43defa.yaml)

*last_updated:* 2026-10-05

{{< /column >}}
{{< /block >}}
