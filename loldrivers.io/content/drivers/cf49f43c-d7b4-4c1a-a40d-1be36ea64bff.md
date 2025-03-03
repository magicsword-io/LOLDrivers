+++

description = ""
title = "cf49f43c-d7b4-4c1a-a40d-1be36ea64bff"
weight = 10
displayTitle = "SysDrv3S.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SysDrv3S.sys ![:inline](/images/twitter_verified.png) 

### Description

Vulnerable driver found in https://github.com/hfiref0x/KDU.
- **UUID**: cf49f43c-d7b4-4c1a-a40d-1be36ea64bff
- **Created**: 2023-05-22
- **Author**: Michael Haag
- **Acknowledgement**: hfiref0x | [hfiref0x](https://twitter.com/hfiref0x)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/31eca8c0b32135850d5a50aee11fec87.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create SysDrv3S.sys binPath=C:\windows\temp\SysDrv3S.sys type=kernel &amp;&amp; sc.exe start SysDrv3S.sys
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
<li><a href="https://github.com/magicsword-io/LOLDrivers/issues/55#issuecomment-1537161951">https://github.com/magicsword-io/LOLDrivers/issues/55#issuecomment-1537161951</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | SysDrv3S.sys |
| Creation Timestamp           | 2016-02-24 05:31:51 |
| MD5                | [31eca8c0b32135850d5a50aee11fec87](https://www.virustotal.com/gui/file/31eca8c0b32135850d5a50aee11fec87) |
| SHA1               | [e1069365cb580e3525090f2fa28efd4127223588](https://www.virustotal.com/gui/file/e1069365cb580e3525090f2fa28efd4127223588) |
| SHA256             | [0e53b58415fa68552928622118d5b8a3a851b2fc512709a90b63ba46acda8b6b](https://www.virustotal.com/gui/file/0e53b58415fa68552928622118d5b8a3a851b2fc512709a90b63ba46acda8b6b) |
| Authentihash MD5   | [0ef111dc998659cbc37f0d9845cdd2df](https://www.virustotal.com/gui/search/authentihash%253A0ef111dc998659cbc37f0d9845cdd2df) |
| Authentihash SHA1  | [432b5809d84935d15574de8d64b22e06682ff715](https://www.virustotal.com/gui/search/authentihash%253A432b5809d84935d15574de8d64b22e06682ff715) |
| Authentihash SHA256| [97cada65b735f3eece349c7b7021c4469d5a9fb3cf8b5e2ac187006469ffbc98](https://www.virustotal.com/gui/search/authentihash%253A97cada65b735f3eece349c7b7021c4469d5a9fb3cf8b5e2ac187006469ffbc98) |
| RichPEHeaderHash MD5   | [4c4e61d23caf453cd98052bd346147af](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A4c4e61d23caf453cd98052bd346147af) |
| RichPEHeaderHash SHA1  | [8cac5443a51b67b2cdcf79e16acf97e900f1cc3b](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8cac5443a51b67b2cdcf79e16acf97e900f1cc3b) |
| RichPEHeaderHash SHA256| [b4312d3ba6a4607ea60df01e1cc8f20eced165f726bb535c437a1c48f63bb1b0](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ab4312d3ba6a4607ea60df01e1cc8f20eced165f726bb535c437a1c48f63bb1b0) |
| Company           | 3S-Smart Software Solutions GmbH |
| Description       | SysDrv3S |
| Product           | SysDrv3S |
| OriginalFilename  | SysDrv3S.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/31eca8c0b32135850d5a50aee11fec87.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 04000000000125071df9af
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | f47739306d14722e670d9436eadb8e4f  |
| ToBeSigned (TBS) SHA1             | 457d9df00a652cb4c3356d00145d9528fc309172 |
| ToBeSigned (TBS) SHA256           | bd1765c56594221373893ef26d97f88c144fb0e5a0111215b45d7239c3444df7 |
| Subject                           | OU=GlobalSign Root CA , R3, O=GlobalSign, CN=GlobalSign |
| ValidFrom                         | 2009-11-18 10:00:00 |
| ValidTo                           | 2019-03-18 10:00:00 |
| Signature                         | 4252a97ea2cf5b3bcb4bddbaf85759d324a47772ef62443782ed06ee04d5165f24a314dc6c54056ab09b3dda8139daad28db956f8183f5cd62b14524b1dd29e5085495958cf01d065f1ad6463f1340174811169b474dd13ab50f571c9230d0f8b2253b0acdf687f9c7b257d33f7da58c14ce9ca8c79f4693da59fa795d652035445a4fc1909dc1549256dc34c8f5c103d05dc059489c00fc95a0f1d176f71636c813927f2d2bc0b880f126261f414d52bf1e97bb018208e715f6c1d5342accf5e4c3877a5781e1d6d74286620177e2a9c47a86f404387a076a7d00ec73f7a80b3478c59eb3efb838400e8c3353c875ec5f3eea755eff820e7415dc1905f3ba31 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 04000000000125071df9af |
| Version                           | 3 |
###### Certificate 481b6a07a9424c1eaafef3cdf10f
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | fd8cfeea06be14fa89689909e1fc72dc  |
| ToBeSigned (TBS) SHA1             | 8bc3cd2f70abe543e0dbe721065a4076c8521f36 |
| ToBeSigned (TBS) SHA256           | 15e7050789df807f3e3174294a01b637a1239f603e42f4b5db9398efa9da9996 |
| Subject                           | C=BE, O=GlobalSign nv,sa, CN=GlobalSign Extended Validation CodeSigning CA , SHA256 , G3 |
| ValidFrom                         | 2016-06-15 00:00:00 |
| ValidTo                           | 2024-06-15 00:00:00 |
| Signature                         | 7609c4cc2fd9ef1e4ba9f857f3403921ca4c3c1d9e292b20d42b44d288ce1a0d05cf8381bbeb69bc318d2ac4c744cc6060941ccfa1e102240ead5bbe2cc2271e67b7e8281f3251e339f398dfb89f2e8b2ab47b0a03bcbd36048fc9d09c4fa3022799b0f045e934dfe43aa3b70637d86f2a7990d4d44e5871ec53a96198f73969e0129c575872862729a51de532f32b99975abf2bb03cb406ea0e64ecb7cd65802417c2d937f5b1261035477b9a02ba54a24593ff79bf1a8cc59fb59fdf78e76b50f14794694b24b8da05e80c9d4f06ec4a31207e4f5d86842f35a3cd9cc184571f1fadc0e2a4b1ef296b2197a6d4feed0337b0fcf58d2abcdc8483e3dec3e75f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 481b6a07a9424c1eaafef3cdf10f |
| Version                           | 3 |
###### Certificate 6129152700000000002a
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 0bb058d116f02817737920f112d9fd3b  |
| ToBeSigned (TBS) SHA1             | fd116235171a4feafedee586b7a59185fb5fd7e6 |
| ToBeSigned (TBS) SHA256           | f970426cc46d2ae0fc5f899fa19dbe76e05f07e525654c60c3c9399492c291f4 |
| Subject                           | C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA |
| ValidFrom                         | 2011-04-15 19:55:08 |
| ValidTo                           | 2021-04-15 20:05:08 |
| Signature                         | 5ff8d065746a81c6a6ca5b03b6914ae84bbdef2ba142f0efb4a5adcd3389ec0b9585ac62501108aa58d25aa08310e5a6337af25af2c5fe787cf09c83df190ad97396002dd62ccde914d41d9de83f3c1a76f7904efb01350a6c9313a0c356eb67a0e4d17a96dec267f190f80a7bf5321b94ec5f751f8d1b34da6c58a7cb2d279e2226b7c9aa30cc0777b836e38201b5393ccc8dd9a75f7f23b3877fdb5798918bd7ce2520e39d644fdd87f72b68490318e0a5df7c5f68644d36838d4781f2e9e0a869abfa7b163c05a449ea8830190a6c73055178dfd41ddd3ad47f2de44e54be83431e7a7433b4a4ebd77073bc2a02988966eef6bc8f749378e329025a5a43e258ce7ccf9acad236893be25fda26054ec8d4e72c910e1797c5beee8b13112323294ffa83d050f6bafad53db3173df4ff034aa325dce67561d1fa35086bd62744d068b78d45e0eb852cc8a15d614474160e5958aed2b5eea5bcd6d7076ab62978fd976767dd8d4f17944fd2ed0caf972437c3a29c81da6be143b6577b4cecbf791319e79fe844e94781b75e701e91f83dd17b27f50b7056434805dda92fab86101d0b12e31ad04c6e75ded645b30b748887935c564a41029af7aeb799d8b67f88fa11f2457cf4d71b91c01cf1a0fbd4080a411a142acef4eb34486e66879ed54b7a397fbb0e3d3861cf735706e412066bd96b5308cd7018c22d4f974691bca9f0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 6129152700000000002a |
| Version                           | 3 |
###### Certificate 60a8b030535055def1677cc6
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | e3f11dbfce17755c33f8e88f75d1920e  |
| ToBeSigned (TBS) SHA1             | 78dcece49b4dbff1bd9a4d66644961c0805aef51 |
| ToBeSigned (TBS) SHA256           | f8e8df9ee7f7b09507e2c889d366c16a4383d87ff22d2c01808b116a4898d5d3 |
| Subject                           | ??=Private Organization, serialNumber=HRB 6186, ??=DE, ??=Bayern, ??=Kempten (Allgaeu), C=DE, ST=Bayern, L=Kempten (Allgu), ??=Memminger Str. 151, O=3S,Smart Software Solutions GmbH, CN=3S,Smart Software Solutions GmbH, emailAddress=info@codesys.com |
| ValidFrom                         | 2019-02-01 15:34:02 |
| ValidTo                           | 2021-02-01 15:34:02 |
| Signature                         | 80dad6d1dcb4d50486f485a5309cfafec484503d27a24a02d63b1343782a476cf76e64e32c7dfc9aca28cbdcc636c4ce4da1da4dd72f613fa54c68489ee8331b4fc66399ea933533a946e4f30f64f2ee09d592c06d1482c128e6d2c8cf0b5321a919bece3e8338c86717291eb589575bd3780e66a24111a1fa3975ffd0df0e779cf4a3ec9ecb06a7a6d89e6467d9104742fe3be7af25d1adf7e3583159a852d82e64b7b4c5f9134dbab58e4d736204e1bfdf0a66121fd9cb0a674ffac58e4de9019444329e5dd5d81770c24fc4529c52f527f473cd2ecb27b97e68b2486db25f8c2c4ced516f0c18cf1cb4b36d09109d88d20ba6b5259f4b6405c5d268718a97 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 60a8b030535055def1677cc6 |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* HAL.dll
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* HalSetBusDataByOffset
* HalTranslateBusAddress
* HalGetBusData
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* DbgPrint
* IofCompleteRequest
* ZwUnmapViewOfSection
* RtlAssert
* IoDeleteSymbolicLink
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlQueryRegistryValues
* RtlWriteRegistryValue
* ZwCreateFile
* ZwReadFile
* ZwWriteFile
* ZwQueryInformationFile
* KeSetEvent
* KeWaitForSingleObject
* IofCallDriver
* KeInitializeEvent
* IoGetDeviceProperty
* __C_specific_handler
* IoDetachDevice
* RtlFreeUnicodeString
* IoAttachDeviceToDeviceStack
* RtlCopyUnicodeString
* ExAllocatePool
* PoCallDriver
* PoStartNextPowerIrp
* IoFreeIrp
* IoAllocateIrp

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .gdat
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
      "SerialNumber": "04000000000125071df9af",
      "Signature": "4252a97ea2cf5b3bcb4bddbaf85759d324a47772ef62443782ed06ee04d5165f24a314dc6c54056ab09b3dda8139daad28db956f8183f5cd62b14524b1dd29e5085495958cf01d065f1ad6463f1340174811169b474dd13ab50f571c9230d0f8b2253b0acdf687f9c7b257d33f7da58c14ce9ca8c79f4693da59fa795d652035445a4fc1909dc1549256dc34c8f5c103d05dc059489c00fc95a0f1d176f71636c813927f2d2bc0b880f126261f414d52bf1e97bb018208e715f6c1d5342accf5e4c3877a5781e1d6d74286620177e2a9c47a86f404387a076a7d00ec73f7a80b3478c59eb3efb838400e8c3353c875ec5f3eea755eff820e7415dc1905f3ba31",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "OU=GlobalSign Root CA , R3, O=GlobalSign, CN=GlobalSign",
      "TBS": {
        "MD5": "f47739306d14722e670d9436eadb8e4f",
        "SHA1": "457d9df00a652cb4c3356d00145d9528fc309172",
        "SHA256": "bd1765c56594221373893ef26d97f88c144fb0e5a0111215b45d7239c3444df7",
        "SHA384": "b8b268a1bdf388be66a1c969b7b353cb2bbc9fad446049b7efa05a9ab3b714494e97f4d1ee1c0bae35bfd9bf6ef275b3"
      },
      "ValidFrom": "2009-11-18 10:00:00",
      "ValidTo": "2019-03-18 10:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "481b6a07a9424c1eaafef3cdf10f",
      "Signature": "7609c4cc2fd9ef1e4ba9f857f3403921ca4c3c1d9e292b20d42b44d288ce1a0d05cf8381bbeb69bc318d2ac4c744cc6060941ccfa1e102240ead5bbe2cc2271e67b7e8281f3251e339f398dfb89f2e8b2ab47b0a03bcbd36048fc9d09c4fa3022799b0f045e934dfe43aa3b70637d86f2a7990d4d44e5871ec53a96198f73969e0129c575872862729a51de532f32b99975abf2bb03cb406ea0e64ecb7cd65802417c2d937f5b1261035477b9a02ba54a24593ff79bf1a8cc59fb59fdf78e76b50f14794694b24b8da05e80c9d4f06ec4a31207e4f5d86842f35a3cd9cc184571f1fadc0e2a4b1ef296b2197a6d4feed0337b0fcf58d2abcdc8483e3dec3e75f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign Extended Validation CodeSigning CA , SHA256 , G3",
      "TBS": {
        "MD5": "fd8cfeea06be14fa89689909e1fc72dc",
        "SHA1": "8bc3cd2f70abe543e0dbe721065a4076c8521f36",
        "SHA256": "15e7050789df807f3e3174294a01b637a1239f603e42f4b5db9398efa9da9996",
        "SHA384": "8b9f95e6d3dd45e4ef38e2f12fb893d7d1bb1ba867e152e4a73c49b3d51dd52bc83a05982deac29af90436061248546d"
      },
      "ValidFrom": "2016-06-15 00:00:00",
      "ValidTo": "2024-06-15 00:00:00",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "6129152700000000002a",
      "Signature": "5ff8d065746a81c6a6ca5b03b6914ae84bbdef2ba142f0efb4a5adcd3389ec0b9585ac62501108aa58d25aa08310e5a6337af25af2c5fe787cf09c83df190ad97396002dd62ccde914d41d9de83f3c1a76f7904efb01350a6c9313a0c356eb67a0e4d17a96dec267f190f80a7bf5321b94ec5f751f8d1b34da6c58a7cb2d279e2226b7c9aa30cc0777b836e38201b5393ccc8dd9a75f7f23b3877fdb5798918bd7ce2520e39d644fdd87f72b68490318e0a5df7c5f68644d36838d4781f2e9e0a869abfa7b163c05a449ea8830190a6c73055178dfd41ddd3ad47f2de44e54be83431e7a7433b4a4ebd77073bc2a02988966eef6bc8f749378e329025a5a43e258ce7ccf9acad236893be25fda26054ec8d4e72c910e1797c5beee8b13112323294ffa83d050f6bafad53db3173df4ff034aa325dce67561d1fa35086bd62744d068b78d45e0eb852cc8a15d614474160e5958aed2b5eea5bcd6d7076ab62978fd976767dd8d4f17944fd2ed0caf972437c3a29c81da6be143b6577b4cecbf791319e79fe844e94781b75e701e91f83dd17b27f50b7056434805dda92fab86101d0b12e31ad04c6e75ded645b30b748887935c564a41029af7aeb799d8b67f88fa11f2457cf4d71b91c01cf1a0fbd4080a411a142acef4eb34486e66879ed54b7a397fbb0e3d3861cf735706e412066bd96b5308cd7018c22d4f974691bca9f0",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA",
      "TBS": {
        "MD5": "0bb058d116f02817737920f112d9fd3b",
        "SHA1": "fd116235171a4feafedee586b7a59185fb5fd7e6",
        "SHA256": "f970426cc46d2ae0fc5f899fa19dbe76e05f07e525654c60c3c9399492c291f4",
        "SHA384": "c0df876be008c26ca407fe904e6f5e7ccded17f9c16830ce9f8022309c9e64c97f494810f152811ae43e223b82ad7cc6"
      },
      "ValidFrom": "2011-04-15 19:55:08",
      "ValidTo": "2021-04-15 20:05:08",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "60a8b030535055def1677cc6",
      "Signature": "80dad6d1dcb4d50486f485a5309cfafec484503d27a24a02d63b1343782a476cf76e64e32c7dfc9aca28cbdcc636c4ce4da1da4dd72f613fa54c68489ee8331b4fc66399ea933533a946e4f30f64f2ee09d592c06d1482c128e6d2c8cf0b5321a919bece3e8338c86717291eb589575bd3780e66a24111a1fa3975ffd0df0e779cf4a3ec9ecb06a7a6d89e6467d9104742fe3be7af25d1adf7e3583159a852d82e64b7b4c5f9134dbab58e4d736204e1bfdf0a66121fd9cb0a674ffac58e4de9019444329e5dd5d81770c24fc4529c52f527f473cd2ecb27b97e68b2486db25f8c2c4ced516f0c18cf1cb4b36d09109d88d20ba6b5259f4b6405c5d268718a97",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=Private Organization, serialNumber=HRB 6186, ??=DE, ??=Bayern, ??=Kempten (Allgaeu), C=DE, ST=Bayern, L=Kempten (Allgu), ??=Memminger Str. 151, O=3S,Smart Software Solutions GmbH, CN=3S,Smart Software Solutions GmbH, emailAddress=info@codesys.com",
      "TBS": {
        "MD5": "e3f11dbfce17755c33f8e88f75d1920e",
        "SHA1": "78dcece49b4dbff1bd9a4d66644961c0805aef51",
        "SHA256": "f8e8df9ee7f7b09507e2c889d366c16a4383d87ff22d2c01808b116a4898d5d3",
        "SHA384": "012b1e87cc98ed598fd4dc3a8fccba9328af6fa73510f4fd613b5e2fbe031815f008046be97c766c5f0ab9367e89173b"
      },
      "ValidFrom": "2019-02-01 15:34:02",
      "ValidTo": "2021-02-01 15:34:02",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=BE, O=GlobalSign nv,sa, CN=GlobalSign Extended Validation CodeSigning CA , SHA256 , G3",
      "SerialNumber": "60a8b030535055def1677cc6",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/cf49f43c-d7b4-4c1a-a40d-1be36ea64bff.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
