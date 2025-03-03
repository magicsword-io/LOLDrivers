+++

description = ""
title = "fab98aaa-e4e7-4c4a-af65-c00d35cf66e9"
weight = 10
displayTitle = "cpuz141.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# cpuz141.sys ![:inline](/images/twitter_verified.png) 

### Description

cpuz141.sys is a vulnerable driver and more information will be added as found.
- **UUID**: fab98aaa-e4e7-4c4a-af65-c00d35cf66e9
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/db72def618cbc3c5f9aa82f091b54250.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create cpuz141.sys binPath=C:\windows\temp\cpuz141.sys type=kernel &amp;&amp; sc.exe start cpuz141.sys
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
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | cpuz141.sys |
| Creation Timestamp           | 2016-11-22 06:20:59 |
| MD5                | [db72def618cbc3c5f9aa82f091b54250](https://www.virustotal.com/gui/file/db72def618cbc3c5f9aa82f091b54250) |
| SHA1               | [f5696fb352a3fbd14fb1a89ad21a71776027f9ab](https://www.virustotal.com/gui/file/f5696fb352a3fbd14fb1a89ad21a71776027f9ab) |
| SHA256             | [ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d](https://www.virustotal.com/gui/file/ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d) |
| Authentihash MD5   | [17b67e675e778c70d3c348d5088ab514](https://www.virustotal.com/gui/search/authentihash%253A17b67e675e778c70d3c348d5088ab514) |
| Authentihash SHA1  | [b38b98608e410c1555a7d73056e86e1db850bb2e](https://www.virustotal.com/gui/search/authentihash%253Ab38b98608e410c1555a7d73056e86e1db850bb2e) |
| Authentihash SHA256| [33b88ac3151f2192eaf4c2be3c7ad00e49090c8b94ec51b754e19ac784b087aa](https://www.virustotal.com/gui/search/authentihash%253A33b88ac3151f2192eaf4c2be3c7ad00e49090c8b94ec51b754e19ac784b087aa) |
| RichPEHeaderHash MD5   | [c046d6f14ec39d2a0f67a417bda83c5e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac046d6f14ec39d2a0f67a417bda83c5e) |
| RichPEHeaderHash SHA1  | [74661f1063b4c80566f75a1bee22c35f7af17fa9](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A74661f1063b4c80566f75a1bee22c35f7af17fa9) |
| RichPEHeaderHash SHA256| [440eebbdc09d290724d364056ba4e2725c75759819a6df0a1ed5c876ed7d2474](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A440eebbdc09d290724d364056ba4e2725c75759819a6df0a1ed5c876ed7d2474) |
| Publisher         | CPUID |
| Company           | CPUID |
| Description       | CPUID Driver |
| Product           | CPUID service |
| OriginalFilename  | cpuz.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/db72def618cbc3c5f9aa82f091b54250.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
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
###### Certificate 2d8021d84f098e7abde199f818e211a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 8f8c7ccf1ef7e1ee347f49e8266008ca  |
| ToBeSigned (TBS) SHA1             | b856b993df73da9d824aa1e5161788bd10d1e10e |
| ToBeSigned (TBS) SHA256           | 1dd13a417806106c76cfbcd3614fe27a0638d2aaf2731f6a110c05043e34ad91 |
| Subject                           | C=FR, ST=NORD, L=DUNKERQUE, O=CPUID, CN=CPUID |
| ValidFrom                         | 2014-12-02 00:00:00 |
| ValidTo                           | 2018-03-02 23:59:59 |
| Signature                         | a59808b35f916a1201f0987b958aaaf50b81f3e507cf9d1b902bc22787244617e38069e4ca74bcf505dfdfeb6bad8bee2ecba26a428c2b26c9b9987241b50ccfd895a7335b35534c5569fdef2554d773cb3b20f10e08eeff2701d2a3e8ef7c5bb759baf1995d1580dce4f0c5da90eff4f07e01e7c9273b24c14c514f2ae1d1fe940dd53bfa25572cd6f3c007c7f21aebc58ea32ca3aea83c731419c9dcc191158cbb52b0b70545a16c9b42aadd4dcb167443d6c15fa03ae7f6f0f644845a69cb8badb3f143fd916a70c5008c3486d1f0cc8e0527f76da5aeaca4925f6eb6861dd54e1ce8b80e6b000446d77ac8bd0299e38db3b8e4a9c43294367cd6a55351d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 2d8021d84f098e7abde199f818e211a4 |
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
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* IoCancelIrp
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* RtlAnsiStringToUnicodeString
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* KeBugCheckEx
* ExFreePoolWithTag
* IoDeleteSymbolicLink
* IoBuildDeviceIoControlRequest
* MmMapIoSpace
* ExAllocatePoolWithTag
* RtlUnwindEx
* HalGetBusDataByOffset
* HalSetBusDataByOffset
* KeStallExecutionProcessor
* KeQueryPerformanceCounter

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
* .rsrc

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
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
      "SerialNumber": "2d8021d84f098e7abde199f818e211a4",
      "Signature": "a59808b35f916a1201f0987b958aaaf50b81f3e507cf9d1b902bc22787244617e38069e4ca74bcf505dfdfeb6bad8bee2ecba26a428c2b26c9b9987241b50ccfd895a7335b35534c5569fdef2554d773cb3b20f10e08eeff2701d2a3e8ef7c5bb759baf1995d1580dce4f0c5da90eff4f07e01e7c9273b24c14c514f2ae1d1fe940dd53bfa25572cd6f3c007c7f21aebc58ea32ca3aea83c731419c9dcc191158cbb52b0b70545a16c9b42aadd4dcb167443d6c15fa03ae7f6f0f644845a69cb8badb3f143fd916a70c5008c3486d1f0cc8e0527f76da5aeaca4925f6eb6861dd54e1ce8b80e6b000446d77ac8bd0299e38db3b8e4a9c43294367cd6a55351d0",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=FR, ST=NORD, L=DUNKERQUE, O=CPUID, CN=CPUID",
      "TBS": {
        "MD5": "8f8c7ccf1ef7e1ee347f49e8266008ca",
        "SHA1": "b856b993df73da9d824aa1e5161788bd10d1e10e",
        "SHA256": "1dd13a417806106c76cfbcd3614fe27a0638d2aaf2731f6a110c05043e34ad91",
        "SHA384": "d24ede407b82f80a6f0703b59af267f227a956c21f642f4c3d717d6999728ba2acfde76966340f4334f8ecdcf294616e"
      },
      "ValidFrom": "2014-12-02 00:00:00",
      "ValidTo": "2018-03-02 23:59:59",
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
      "SerialNumber": "2d8021d84f098e7abde199f818e211a4",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fab98aaa-e4e7-4c4a-af65-c00d35cf66e9.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
