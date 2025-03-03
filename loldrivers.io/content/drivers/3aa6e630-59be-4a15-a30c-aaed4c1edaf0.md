+++

description = ""
title = "3aa6e630-59be-4a15-a30c-aaed4c1edaf0"
weight = 10
displayTitle = "kerneld.amd64"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# kerneld.amd64 ![:inline](/images/twitter_verified.png) 

### Description

The Carbon Black Threat Analysis Unit (TAU) discovered 34 unique vulnerable drivers (237 file hashes) accepting firmware access. Six allow kernel memory access. All give full control of the devices to non-admin users. By exploiting the vulnerable drivers, an attacker without the system privilege may erase/alter firmware, and/or elevate privileges. As of the time of writing in October 2023, the filenames of the vulnerable drivers have not been made public until now.
- **UUID**: 3aa6e630-59be-4a15-a30c-aaed4c1edaf0
- **Created**: 2023-11-02
- **Author**: Takahiro Haruyama
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7575b35fee4ec8dbd0a61dbca3b972e3.bin" "Download" >}}{{< button "https://www.magicsword.io/premium" "Block" "red" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create kerneldamd64 binPath= C:\windows\temp\kerneldamd64.sys type=kernel &amp;&amp; sc.exe start kerneldamd64
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
| Creation Timestamp           | 2010-06-17 15:13:48 |
| MD5                | [7575b35fee4ec8dbd0a61dbca3b972e3](https://www.virustotal.com/gui/file/7575b35fee4ec8dbd0a61dbca3b972e3) |
| SHA1               | [76a756cc61653abcadd63db4a74c48d92607a861](https://www.virustotal.com/gui/file/76a756cc61653abcadd63db4a74c48d92607a861) |
| SHA256             | [065a34b786b0ccf6f88c136408943c3d2bd3da14357ee1e55e81e05d67a4c9bc](https://www.virustotal.com/gui/file/065a34b786b0ccf6f88c136408943c3d2bd3da14357ee1e55e81e05d67a4c9bc) |
| Authentihash MD5   | [466c85cd235caf91a0a7c8b4a09c3865](https://www.virustotal.com/gui/search/authentihash%253A466c85cd235caf91a0a7c8b4a09c3865) |
| Authentihash SHA1  | [ac56dd7722a47e33ba0924aaa6062f74bfc1c08f](https://www.virustotal.com/gui/search/authentihash%253Aac56dd7722a47e33ba0924aaa6062f74bfc1c08f) |
| Authentihash SHA256| [88188ebb2dd61397d816274645cce6044489675a52d835faf518b2d137e0604c](https://www.virustotal.com/gui/search/authentihash%253A88188ebb2dd61397d816274645cce6044489675a52d835faf518b2d137e0604c) |
| RichPEHeaderHash MD5   | [e93b5a02ff5f4c18b186ee8c35f3132e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae93b5a02ff5f4c18b186ee8c35f3132e) |
| RichPEHeaderHash SHA1  | [897dc8e1b30df0d168feda245816e72aa2cfcf9e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A897dc8e1b30df0d168feda245816e72aa2cfcf9e) |
| RichPEHeaderHash SHA256| [377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7575b35fee4ec8dbd0a61dbca3b972e3.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* IoBuildDeviceIoControlRequest
* MmIsAddressValid
* IoDeleteSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* MmMapIoSpace
* RtlInitUnicodeString
* IofCallDriver
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* RtlFreeUnicodeString
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2005-11-20 09:21:24 |
| MD5                | [397580c24c544d477688fcfca9c9b542](https://www.virustotal.com/gui/file/397580c24c544d477688fcfca9c9b542) |
| SHA1               | [4a1a499857accc04b4d586df3f0e0c2b3546e825](https://www.virustotal.com/gui/file/4a1a499857accc04b4d586df3f0e0c2b3546e825) |
| SHA256             | [0c018eaa293c03febe2aef1e868fca782a06b49d7d2f9f388ae5fb57604c5250](https://www.virustotal.com/gui/file/0c018eaa293c03febe2aef1e868fca782a06b49d7d2f9f388ae5fb57604c5250) |
| Authentihash MD5   | [63ed411f59c8050e042b29626a4bd605](https://www.virustotal.com/gui/search/authentihash%253A63ed411f59c8050e042b29626a4bd605) |
| Authentihash SHA1  | [1d0e2dc0d10e2c6d0f902498a9f07f30de032e3c](https://www.virustotal.com/gui/search/authentihash%253A1d0e2dc0d10e2c6d0f902498a9f07f30de032e3c) |
| Authentihash SHA256| [77aabfc119686757d31cc9d21af9bf3bacecaae09dc92e548355a145db0aa774](https://www.virustotal.com/gui/search/authentihash%253A77aabfc119686757d31cc9d21af9bf3bacecaae09dc92e548355a145db0aa774) |
| RichPEHeaderHash MD5   | [d8efbf77a16c80060c37681f4fc696d7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad8efbf77a16c80060c37681f4fc696d7) |
| RichPEHeaderHash SHA1  | [74f746e5eebab46d9ee2e15c96542fa508bdd271](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A74f746e5eebab46d9ee2e15c96542fa508bdd271) |
| RichPEHeaderHash SHA256| [c6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/397580c24c544d477688fcfca9c9b542.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlAssert
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-02-17 11:47:03 |
| MD5                | [13a2b915f6d93e52505656773d53096f](https://www.virustotal.com/gui/file/13a2b915f6d93e52505656773d53096f) |
| SHA1               | [336ed563ef96c40eece92a4d13de9f9b69991c8a](https://www.virustotal.com/gui/file/336ed563ef96c40eece92a4d13de9f9b69991c8a) |
| SHA256             | [125e4475a5437634cab529da9ea2ef0f4f65f89fb25a06349d731f283c27d9fe](https://www.virustotal.com/gui/file/125e4475a5437634cab529da9ea2ef0f4f65f89fb25a06349d731f283c27d9fe) |
| Authentihash MD5   | [e80ddfe5a816dd6cb2ffd72da610d8db](https://www.virustotal.com/gui/search/authentihash%253Ae80ddfe5a816dd6cb2ffd72da610d8db) |
| Authentihash SHA1  | [a7e50663be8f7e859b63d1d266e8263a96f7520b](https://www.virustotal.com/gui/search/authentihash%253Aa7e50663be8f7e859b63d1d266e8263a96f7520b) |
| Authentihash SHA256| [f6e714528ad1b9eae72699078499735468140c1627e45f015762206ba7a77b47](https://www.virustotal.com/gui/search/authentihash%253Af6e714528ad1b9eae72699078499735468140c1627e45f015762206ba7a77b47) |
| RichPEHeaderHash MD5   | [510491d926769fc79a5d3287db0dd59d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A510491d926769fc79a5d3287db0dd59d) |
| RichPEHeaderHash SHA1  | [32af9e7e3a31bd44e3a5d717efcbe898d17c2423](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A32af9e7e3a31bd44e3a5d717efcbe898d17c2423) |
| RichPEHeaderHash SHA256| [8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/13a2b915f6d93e52505656773d53096f.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* MmUnmapIoSpace
* IoCreateDevice
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* IofCallDriver
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeBugCheckEx
* RtlInitAnsiString
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2006-12-14 15:42:31 |
| MD5                | [723381977ce7df57ec623db52b84f426](https://www.virustotal.com/gui/file/723381977ce7df57ec623db52b84f426) |
| SHA1               | [64879accdb4dbbaac55d91185c82f2b193f0c869](https://www.virustotal.com/gui/file/64879accdb4dbbaac55d91185c82f2b193f0c869) |
| SHA256             | [1336469ec0711736e742b730d356af23f8139da6038979cfe4de282de1365d3b](https://www.virustotal.com/gui/file/1336469ec0711736e742b730d356af23f8139da6038979cfe4de282de1365d3b) |
| Authentihash MD5   | [a493ab091afa9ccafb39f0b73b8cfcc0](https://www.virustotal.com/gui/search/authentihash%253Aa493ab091afa9ccafb39f0b73b8cfcc0) |
| Authentihash SHA1  | [17b3417429a0d5e10492a243a4b7c3232c2a303c](https://www.virustotal.com/gui/search/authentihash%253A17b3417429a0d5e10492a243a4b7c3232c2a303c) |
| Authentihash SHA256| [2418301336cd89b7e3bda2f68bc1aa63b8ea9a75da7a3b40a9ee0a9058789f63](https://www.virustotal.com/gui/search/authentihash%253A2418301336cd89b7e3bda2f68bc1aa63b8ea9a75da7a3b40a9ee0a9058789f63) |
| RichPEHeaderHash MD5   | [d7c3e34ff185cd060fd272724a9a08d4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad7c3e34ff185cd060fd272724a9a08d4) |
| RichPEHeaderHash SHA1  | [07bd4ac3ba36186190def09485c7e9ecdaae1d12](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A07bd4ac3ba36186190def09485c7e9ecdaae1d12) |
| RichPEHeaderHash SHA256| [e886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/723381977ce7df57ec623db52b84f426.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 0de92bf0d4d82988183205095e9a7688
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 45c204b8a20f6abb0188d2d38a3fb0c9  |
| ToBeSigned (TBS) SHA1             | cdf3a3c5c2eda4c29621f30fd3154f9f8c765739 |
| ToBeSigned (TBS) SHA256           | e32839dddc0f4ed2474efaf37f59d46db400c700fd19533cb0895a111124bc77 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2008-12-03 23:59:59 |
| Signature                         | 877870da4e5201205be079c98230c4fdb91996bd9100c3bdcdcdc6f40ed8fff94dc033623011c5f5741bd492de5f9c2013b17c45be50cd83e7801783a72793671346fbcab8984103cc9b515b058b7fa86ff31b501b242ef2698d6c22f7bbca1695ed0c74c06877d9eb996287c17390f889747a23aba3987b97b1f78f29714d2e751b4841daf0b50d2054d677a097826369fd09cf8af075bb099bd9f91155269a6132be7a02b07b86bea2c38b222c78d13576bc92735cf9b9e64c150a23cce4d2d4342e4940153c0f607a24c6a566ef96cf70eb3ee7f40d7edcd17ca3767169c19c4f47303521b1a2af1a623c2bd98eaa2a077bd818b35c7be29da56ffe3c89ad |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0de92bf0d4d82988183205095e9a7688 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2009-02-09 15:09:02 |
| MD5                | [eb7f6d01c97783013115ad1a2833401a](https://www.virustotal.com/gui/file/eb7f6d01c97783013115ad1a2833401a) |
| SHA1               | [fb4ce6de14f2be00a137e8dde2c68bb5b137ab9c](https://www.virustotal.com/gui/file/fb4ce6de14f2be00a137e8dde2c68bb5b137ab9c) |
| SHA256             | [18047c2d45758a43d6b7e56bcd4aa90354c899795baf944f037850c48d8e892a](https://www.virustotal.com/gui/file/18047c2d45758a43d6b7e56bcd4aa90354c899795baf944f037850c48d8e892a) |
| Authentihash MD5   | [454cb91cd9e825556face4b03c90aaf3](https://www.virustotal.com/gui/search/authentihash%253A454cb91cd9e825556face4b03c90aaf3) |
| Authentihash SHA1  | [65369c73cfe6d634fae882a8a8a1dadedd8d6d5f](https://www.virustotal.com/gui/search/authentihash%253A65369c73cfe6d634fae882a8a8a1dadedd8d6d5f) |
| Authentihash SHA256| [7690ef2838bda2327116243c1792090125b36a5840464e010acdd103f7369807](https://www.virustotal.com/gui/search/authentihash%253A7690ef2838bda2327116243c1792090125b36a5840464e010acdd103f7369807) |
| RichPEHeaderHash MD5   | [eb7a6452e7d8e135bf9199524118601d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aeb7a6452e7d8e135bf9199524118601d) |
| RichPEHeaderHash SHA1  | [7400103f42e22809e66c207f1eb1d22cd947f22f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7400103f42e22809e66c207f1eb1d22cd947f22f) |
| RichPEHeaderHash SHA256| [7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/eb7f6d01c97783013115ad1a2833401a.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2006-10-18 12:56:31 |
| MD5                | [b62e2371158a082e239f5883bd6000d1](https://www.virustotal.com/gui/file/b62e2371158a082e239f5883bd6000d1) |
| SHA1               | [820d339fd3dbb632a790d6506ddf6aee925fcffe](https://www.virustotal.com/gui/file/820d339fd3dbb632a790d6506ddf6aee925fcffe) |
| SHA256             | [212c05b487cd4e64de2a1077b789e47e9ac3361efa24d9aab3cc6ad4bd3bd76a](https://www.virustotal.com/gui/file/212c05b487cd4e64de2a1077b789e47e9ac3361efa24d9aab3cc6ad4bd3bd76a) |
| Authentihash MD5   | [3baddddc6c55bc8262f5f35eebc243df](https://www.virustotal.com/gui/search/authentihash%253A3baddddc6c55bc8262f5f35eebc243df) |
| Authentihash SHA1  | [bba9bf70e503a3f7f67f3f29ccaa7844818651b0](https://www.virustotal.com/gui/search/authentihash%253Abba9bf70e503a3f7f67f3f29ccaa7844818651b0) |
| Authentihash SHA256| [533b8138ab8f776008ff8918c8cfa52604e43efca4e39da5096404c8424084b7](https://www.virustotal.com/gui/search/authentihash%253A533b8138ab8f776008ff8918c8cfa52604e43efca4e39da5096404c8424084b7) |
| RichPEHeaderHash MD5   | [d7c3e34ff185cd060fd272724a9a08d4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad7c3e34ff185cd060fd272724a9a08d4) |
| RichPEHeaderHash SHA1  | [07bd4ac3ba36186190def09485c7e9ecdaae1d12](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A07bd4ac3ba36186190def09485c7e9ecdaae1d12) |
| RichPEHeaderHash SHA256| [e886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b62e2371158a082e239f5883bd6000d1.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 0de92bf0d4d82988183205095e9a7688
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 45c204b8a20f6abb0188d2d38a3fb0c9  |
| ToBeSigned (TBS) SHA1             | cdf3a3c5c2eda4c29621f30fd3154f9f8c765739 |
| ToBeSigned (TBS) SHA256           | e32839dddc0f4ed2474efaf37f59d46db400c700fd19533cb0895a111124bc77 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2008-12-03 23:59:59 |
| Signature                         | 877870da4e5201205be079c98230c4fdb91996bd9100c3bdcdcdc6f40ed8fff94dc033623011c5f5741bd492de5f9c2013b17c45be50cd83e7801783a72793671346fbcab8984103cc9b515b058b7fa86ff31b501b242ef2698d6c22f7bbca1695ed0c74c06877d9eb996287c17390f889747a23aba3987b97b1f78f29714d2e751b4841daf0b50d2054d677a097826369fd09cf8af075bb099bd9f91155269a6132be7a02b07b86bea2c38b222c78d13576bc92735cf9b9e64c150a23cce4d2d4342e4940153c0f607a24c6a566ef96cf70eb3ee7f40d7edcd17ca3767169c19c4f47303521b1a2af1a623c2bd98eaa2a077bd818b35c7be29da56ffe3c89ad |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 0de92bf0d4d82988183205095e9a7688 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-08-29 05:38:31 |
| MD5                | [09e77d71d626574e6142894caca6e6dd](https://www.virustotal.com/gui/file/09e77d71d626574e6142894caca6e6dd) |
| SHA1               | [6b90a6eeef66bb9302665081e30bf9802ca956cc](https://www.virustotal.com/gui/file/6b90a6eeef66bb9302665081e30bf9802ca956cc) |
| SHA256             | [33bc9a17a0909e32a3ae7e6f089b7f050591dd6f3f7a8172575606bec01889ef](https://www.virustotal.com/gui/file/33bc9a17a0909e32a3ae7e6f089b7f050591dd6f3f7a8172575606bec01889ef) |
| Authentihash MD5   | [464331a14dd967eed95bb16a8ccf6127](https://www.virustotal.com/gui/search/authentihash%253A464331a14dd967eed95bb16a8ccf6127) |
| Authentihash SHA1  | [8c0999041d3212be1510a766dcc8b7f4b2401fcf](https://www.virustotal.com/gui/search/authentihash%253A8c0999041d3212be1510a766dcc8b7f4b2401fcf) |
| Authentihash SHA256| [1126c9b043872383e5e0b1ac893ddf2238a2c130401627b259c81d98a3cefeae](https://www.virustotal.com/gui/search/authentihash%253A1126c9b043872383e5e0b1ac893ddf2238a2c130401627b259c81d98a3cefeae) |
| RichPEHeaderHash MD5   | [e93b5a02ff5f4c18b186ee8c35f3132e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae93b5a02ff5f4c18b186ee8c35f3132e) |
| RichPEHeaderHash SHA1  | [897dc8e1b30df0d168feda245816e72aa2cfcf9e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A897dc8e1b30df0d168feda245816e72aa2cfcf9e) |
| RichPEHeaderHash SHA256| [377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/09e77d71d626574e6142894caca6e6dd.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 01cc3af0c7b9f02c029c172f6f135621
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 735dfa995ca4af6545a694a22f0fb657  |
| ToBeSigned (TBS) SHA1             | 5957f3ae95e2a195cf0a1f99eeb989350b58f724 |
| ToBeSigned (TBS) SHA256           | 1278201f6ed95445add0bcdc6030e72609f88fa9bdabafb98615e358005025c1 |
| Subject                           | C=HU, ST=Budapest, L=Budapest, O=FinalWire, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=FinalWire |
| ValidFrom                         | 2010-07-29 00:00:00 |
| ValidTo                           | 2012-07-28 23:59:59 |
| Signature                         | 99e136ac112e7c78ce7c6227980b00b97242c5f7fd2e9b7759cd1e4eb323f0e4c36199f581121ce2ea9331fb4421f78feffdffbe83a0bab67a68a8ac5b3f79d7412b78ebed416feb9ab1d3412de204db326c47b2ab415938b7fadccc83ac35ed2cacbd29df428db05fabb874865fbeabf7eea6c6bd87c11292b2d48b8481cc02000ed147203fa6d9902796beba69ad8fef775205295d8537f50ca96b98ac9ccdf64391f07768979df2557742564bdc4a44e96673038495cbfac986dbf89311f445df1874534325f3b70262a9d9dc475cd9259e6dec576e50df06a7817a6033bdbe97c98d4684772864ecc564baa2356375fdf1e75982c96f4d7578a2d945e916 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01cc3af0c7b9f02c029c172f6f135621 |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* IoBuildDeviceIoControlRequest
* MmIsAddressValid
* IoDeleteSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* MmMapIoSpace
* RtlInitUnicodeString
* IofCallDriver
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* RtlFreeUnicodeString
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2005-07-25 09:31:43 |
| MD5                | [24589081b827989b52d954dcd88035d0](https://www.virustotal.com/gui/file/24589081b827989b52d954dcd88035d0) |
| SHA1               | [3aba6dd15260875eb290e9d67992066141aa0bb0](https://www.virustotal.com/gui/file/3aba6dd15260875eb290e9d67992066141aa0bb0) |
| SHA256             | [38535a0e9fc0684308eb5d6aa6284669bc9743f11cb605b79883b8c13ef906ad](https://www.virustotal.com/gui/file/38535a0e9fc0684308eb5d6aa6284669bc9743f11cb605b79883b8c13ef906ad) |
| Authentihash MD5   | [d7c4f6f8457e53df981b1d23ca4683a4](https://www.virustotal.com/gui/search/authentihash%253Ad7c4f6f8457e53df981b1d23ca4683a4) |
| Authentihash SHA1  | [6ccac0c7b891149b5777ae34f3ef824b37c5d89c](https://www.virustotal.com/gui/search/authentihash%253A6ccac0c7b891149b5777ae34f3ef824b37c5d89c) |
| Authentihash SHA256| [559ef0d415c5c3dbc1bfd598f4cad75aac9d4c5c6660fb61b23e44da4dbf89a9](https://www.virustotal.com/gui/search/authentihash%253A559ef0d415c5c3dbc1bfd598f4cad75aac9d4c5c6660fb61b23e44da4dbf89a9) |
| RichPEHeaderHash MD5   | [8d8e37a1cfda4252f83be326e779bfa3](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8d8e37a1cfda4252f83be326e779bfa3) |
| RichPEHeaderHash SHA1  | [a988073133ae7870ee3c2dd8d56cd35daec87921](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aa988073133ae7870ee3c2dd8d56cd35daec87921) |
| RichPEHeaderHash SHA256| [10005125c3c5d72631d533f730447e65435123a4a0be6456c54ce9f1fcbcb49f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A10005125c3c5d72631d533f730447e65435123a4a0be6456c54ce9f1fcbcb49f) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/24589081b827989b52d954dcd88035d0.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2008-03-09 05:46:25 |
| MD5                | [8f1255efd2ed0d3b03a02c6b236c06d6](https://www.virustotal.com/gui/file/8f1255efd2ed0d3b03a02c6b236c06d6) |
| SHA1               | [9d44260558807daff61a0cc0c6a8719c3adacd2d](https://www.virustotal.com/gui/file/9d44260558807daff61a0cc0c6a8719c3adacd2d) |
| SHA256             | [442f12adebf7cb166b19e8aead2b0440450fd1f33f5db384a39776bb2656474a](https://www.virustotal.com/gui/file/442f12adebf7cb166b19e8aead2b0440450fd1f33f5db384a39776bb2656474a) |
| Authentihash MD5   | [ec630d38e4fc83dda90206425e7fd4b3](https://www.virustotal.com/gui/search/authentihash%253Aec630d38e4fc83dda90206425e7fd4b3) |
| Authentihash SHA1  | [69b0510afa2625734aead94672f8daf851685ac4](https://www.virustotal.com/gui/search/authentihash%253A69b0510afa2625734aead94672f8daf851685ac4) |
| Authentihash SHA256| [53e15b21cc69a554d4d61ffe531be90364ed7b1bb64fc302d65eaa642c9fa60a](https://www.virustotal.com/gui/search/authentihash%253A53e15b21cc69a554d4d61ffe531be90364ed7b1bb64fc302d65eaa642c9fa60a) |
| RichPEHeaderHash MD5   | [2c53952789ebcf16a337a5ec3ab41667](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c53952789ebcf16a337a5ec3ab41667) |
| RichPEHeaderHash SHA1  | [60852524abfeefc666c143ac7a6d7350244e53be](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A60852524abfeefc666c143ac7a6d7350244e53be) |
| RichPEHeaderHash SHA256| [0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8f1255efd2ed0d3b03a02c6b236c06d6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2008-09-20 15:09:05 |
| MD5                | [f0e21ababe63668fb3fbd02e90cd1fa9](https://www.virustotal.com/gui/file/f0e21ababe63668fb3fbd02e90cd1fa9) |
| SHA1               | [b394f84e093cb144568e18aaf5b857dff77091fa](https://www.virustotal.com/gui/file/b394f84e093cb144568e18aaf5b857dff77091fa) |
| SHA256             | [51f002ee44e46889cf5b99a724dd10cc2bd3e22545e2a2cb3bd6b1dd3af5ba11](https://www.virustotal.com/gui/file/51f002ee44e46889cf5b99a724dd10cc2bd3e22545e2a2cb3bd6b1dd3af5ba11) |
| Authentihash MD5   | [61946eefd0034f3b28914649a13f922f](https://www.virustotal.com/gui/search/authentihash%253A61946eefd0034f3b28914649a13f922f) |
| Authentihash SHA1  | [ed0398cea11d29382f23f3f2e2b7edbd1db4a30e](https://www.virustotal.com/gui/search/authentihash%253Aed0398cea11d29382f23f3f2e2b7edbd1db4a30e) |
| Authentihash SHA256| [b7036cd12dc9e3550239310fd8ff4f14e4266bbd0de3aba7b087068a253b506b](https://www.virustotal.com/gui/search/authentihash%253Ab7036cd12dc9e3550239310fd8ff4f14e4266bbd0de3aba7b087068a253b506b) |
| RichPEHeaderHash MD5   | [2c53952789ebcf16a337a5ec3ab41667](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c53952789ebcf16a337a5ec3ab41667) |
| RichPEHeaderHash SHA1  | [60852524abfeefc666c143ac7a6d7350244e53be](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A60852524abfeefc666c143ac7a6d7350244e53be) |
| RichPEHeaderHash SHA256| [0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f0e21ababe63668fb3fbd02e90cd1fa9.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2009-05-04 06:24:01 |
| MD5                | [648adec580746afbbf59904c1e150c73](https://www.virustotal.com/gui/file/648adec580746afbbf59904c1e150c73) |
| SHA1               | [52ea274e399df8706067fdc5ac52af0480461887](https://www.virustotal.com/gui/file/52ea274e399df8706067fdc5ac52af0480461887) |
| SHA256             | [53b9e423baf946983d03ce309ec5e006ba18c9956dcd97c68a8b714d18c8ffcf](https://www.virustotal.com/gui/file/53b9e423baf946983d03ce309ec5e006ba18c9956dcd97c68a8b714d18c8ffcf) |
| Authentihash MD5   | [4373ad9ecb6656ec9048bb02ac9b0e05](https://www.virustotal.com/gui/search/authentihash%253A4373ad9ecb6656ec9048bb02ac9b0e05) |
| Authentihash SHA1  | [072c44a91e17e74c0256446b893e856658565ea7](https://www.virustotal.com/gui/search/authentihash%253A072c44a91e17e74c0256446b893e856658565ea7) |
| Authentihash SHA256| [713c7a6532cbc952546c3b844ed529b5b285dc29e16036731ceebc6f6431ae77](https://www.virustotal.com/gui/search/authentihash%253A713c7a6532cbc952546c3b844ed529b5b285dc29e16036731ceebc6f6431ae77) |
| RichPEHeaderHash MD5   | [eb7a6452e7d8e135bf9199524118601d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aeb7a6452e7d8e135bf9199524118601d) |
| RichPEHeaderHash SHA1  | [7400103f42e22809e66c207f1eb1d22cd947f22f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7400103f42e22809e66c207f1eb1d22cd947f22f) |
| RichPEHeaderHash SHA256| [7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/648adec580746afbbf59904c1e150c73.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-07-30 08:50:06 |
| MD5                | [5c5973d2caf86e96311f6399513ab8df](https://www.virustotal.com/gui/file/5c5973d2caf86e96311f6399513ab8df) |
| SHA1               | [b82c034e41d463f4e68b0a7d334f2d7611049bcb](https://www.virustotal.com/gui/file/b82c034e41d463f4e68b0a7d334f2d7611049bcb) |
| SHA256             | [582b62ffbcbcdd62c0fc624cdf106545af71078f1edfe1129401d64f3eefaa3a](https://www.virustotal.com/gui/file/582b62ffbcbcdd62c0fc624cdf106545af71078f1edfe1129401d64f3eefaa3a) |
| Authentihash MD5   | [86d3624e6394b8b7869da01c4b1fabce](https://www.virustotal.com/gui/search/authentihash%253A86d3624e6394b8b7869da01c4b1fabce) |
| Authentihash SHA1  | [80a7975e89ff4211b26502d77a52539b2e9d2296](https://www.virustotal.com/gui/search/authentihash%253A80a7975e89ff4211b26502d77a52539b2e9d2296) |
| Authentihash SHA256| [058afe9e93dcc52e64fc0942b80a159b8617608c15462a7a17984de3cc0b8d04](https://www.virustotal.com/gui/search/authentihash%253A058afe9e93dcc52e64fc0942b80a159b8617608c15462a7a17984de3cc0b8d04) |
| RichPEHeaderHash MD5   | [e93b5a02ff5f4c18b186ee8c35f3132e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae93b5a02ff5f4c18b186ee8c35f3132e) |
| RichPEHeaderHash SHA1  | [897dc8e1b30df0d168feda245816e72aa2cfcf9e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A897dc8e1b30df0d168feda245816e72aa2cfcf9e) |
| RichPEHeaderHash SHA256| [377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5c5973d2caf86e96311f6399513ab8df.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* IoBuildDeviceIoControlRequest
* MmIsAddressValid
* IoDeleteSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* MmMapIoSpace
* RtlInitUnicodeString
* IofCallDriver
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* RtlFreeUnicodeString
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2008-12-24 06:50:50 |
| MD5                | [009876ab9cf3a3d4e3fc3afe13ae839e](https://www.virustotal.com/gui/file/009876ab9cf3a3d4e3fc3afe13ae839e) |
| SHA1               | [f85f5e5d747433b274e53c8377bf24fbc08758b6](https://www.virustotal.com/gui/file/f85f5e5d747433b274e53c8377bf24fbc08758b6) |
| SHA256             | [6297556f66cd6619057f3a5b216b314f8a27eebb5fa575ee07a1944aca71ae80](https://www.virustotal.com/gui/file/6297556f66cd6619057f3a5b216b314f8a27eebb5fa575ee07a1944aca71ae80) |
| Authentihash MD5   | [f714ae1fce8bfd53a3c0f468ee55a9d0](https://www.virustotal.com/gui/search/authentihash%253Af714ae1fce8bfd53a3c0f468ee55a9d0) |
| Authentihash SHA1  | [3e8dafe5dc14e00469f89272ff04a04070dbd472](https://www.virustotal.com/gui/search/authentihash%253A3e8dafe5dc14e00469f89272ff04a04070dbd472) |
| Authentihash SHA256| [c3577eeb107de6a0cdf6ac3ee75339f09fd0eb00b4d368bf841b6126af7629a1](https://www.virustotal.com/gui/search/authentihash%253Ac3577eeb107de6a0cdf6ac3ee75339f09fd0eb00b4d368bf841b6126af7629a1) |
| RichPEHeaderHash MD5   | [eb7a6452e7d8e135bf9199524118601d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aeb7a6452e7d8e135bf9199524118601d) |
| RichPEHeaderHash SHA1  | [7400103f42e22809e66c207f1eb1d22cd947f22f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7400103f42e22809e66c207f1eb1d22cd947f22f) |
| RichPEHeaderHash SHA256| [7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/009876ab9cf3a3d4e3fc3afe13ae839e.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2007-08-19 06:38:38 |
| MD5                | [7c887f2b1a56b84d86828529604957db](https://www.virustotal.com/gui/file/7c887f2b1a56b84d86828529604957db) |
| SHA1               | [d6b61c685cfaa36c85f1672ac95844f8293c70d0](https://www.virustotal.com/gui/file/d6b61c685cfaa36c85f1672ac95844f8293c70d0) |
| SHA256             | [680ddece32fe99f056e770cb08641f5b585550798dfdf723441a11364637c7e6](https://www.virustotal.com/gui/file/680ddece32fe99f056e770cb08641f5b585550798dfdf723441a11364637c7e6) |
| Authentihash MD5   | [c8d766097a994d3b8d547fedde645d17](https://www.virustotal.com/gui/search/authentihash%253Ac8d766097a994d3b8d547fedde645d17) |
| Authentihash SHA1  | [d26854aa9937dbd80394010b9aac4ee38669f05f](https://www.virustotal.com/gui/search/authentihash%253Ad26854aa9937dbd80394010b9aac4ee38669f05f) |
| Authentihash SHA256| [5b63080bead00cae92efb917b7a707c6a2d6628a1e90301795617b45273f45e4](https://www.virustotal.com/gui/search/authentihash%253A5b63080bead00cae92efb917b7a707c6a2d6628a1e90301795617b45273f45e4) |
| RichPEHeaderHash MD5   | [d7c3e34ff185cd060fd272724a9a08d4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad7c3e34ff185cd060fd272724a9a08d4) |
| RichPEHeaderHash SHA1  | [07bd4ac3ba36186190def09485c7e9ecdaae1d12](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A07bd4ac3ba36186190def09485c7e9ecdaae1d12) |
| RichPEHeaderHash SHA256| [e886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7c887f2b1a56b84d86828529604957db.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-05-20 14:55:04 |
| MD5                | [1caf5070493459ba029d988dbb2c7422](https://www.virustotal.com/gui/file/1caf5070493459ba029d988dbb2c7422) |
| SHA1               | [8d3be83cf3bb36dbce974654b5330adb38792c2d](https://www.virustotal.com/gui/file/8d3be83cf3bb36dbce974654b5330adb38792c2d) |
| SHA256             | [6ef0b34649186fb98a7431b606e77ee35e755894b038755ba98e577bd51b2c72](https://www.virustotal.com/gui/file/6ef0b34649186fb98a7431b606e77ee35e755894b038755ba98e577bd51b2c72) |
| Authentihash MD5   | [c7fb9ed75eb75fa84189e8b8f6e2b95e](https://www.virustotal.com/gui/search/authentihash%253Ac7fb9ed75eb75fa84189e8b8f6e2b95e) |
| Authentihash SHA1  | [cb6b9f4a6107f9cb4badc05fd7c5f6b1e1d59cf6](https://www.virustotal.com/gui/search/authentihash%253Acb6b9f4a6107f9cb4badc05fd7c5f6b1e1d59cf6) |
| Authentihash SHA256| [5fc66378fe68a380ccfab3521657b38912ca1fe5a8d7c857f591e928ab0b4208](https://www.virustotal.com/gui/search/authentihash%253A5fc66378fe68a380ccfab3521657b38912ca1fe5a8d7c857f591e928ab0b4208) |
| RichPEHeaderHash MD5   | [e93b5a02ff5f4c18b186ee8c35f3132e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae93b5a02ff5f4c18b186ee8c35f3132e) |
| RichPEHeaderHash SHA1  | [897dc8e1b30df0d168feda245816e72aa2cfcf9e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A897dc8e1b30df0d168feda245816e72aa2cfcf9e) |
| RichPEHeaderHash SHA256| [377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1caf5070493459ba029d988dbb2c7422.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* IoBuildDeviceIoControlRequest
* MmIsAddressValid
* IoDeleteSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* MmMapIoSpace
* RtlInitUnicodeString
* IofCallDriver
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* RtlFreeUnicodeString
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2009-05-21 08:26:14 |
| MD5                | [a730b97ab977aa444fa261902822a905](https://www.virustotal.com/gui/file/a730b97ab977aa444fa261902822a905) |
| SHA1               | [9f6883e59fd6c136cfc556b7b388a4c363dc0516](https://www.virustotal.com/gui/file/9f6883e59fd6c136cfc556b7b388a4c363dc0516) |
| SHA256             | [748ccadb6bf6cdf4c5a5a1bb9950ee167d8b27c5817da71d38e2bc922ffce73d](https://www.virustotal.com/gui/file/748ccadb6bf6cdf4c5a5a1bb9950ee167d8b27c5817da71d38e2bc922ffce73d) |
| Authentihash MD5   | [a9c4c3e3e25edf4a2a29635e91fc47dc](https://www.virustotal.com/gui/search/authentihash%253Aa9c4c3e3e25edf4a2a29635e91fc47dc) |
| Authentihash SHA1  | [7299c5b3630e455e851e015db5381768f3735eb6](https://www.virustotal.com/gui/search/authentihash%253A7299c5b3630e455e851e015db5381768f3735eb6) |
| Authentihash SHA256| [43dc82fd548218f0e916687c997291c8056dfdcc5b5f5616833437f96d806a64](https://www.virustotal.com/gui/search/authentihash%253A43dc82fd548218f0e916687c997291c8056dfdcc5b5f5616833437f96d806a64) |
| RichPEHeaderHash MD5   | [eb7a6452e7d8e135bf9199524118601d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aeb7a6452e7d8e135bf9199524118601d) |
| RichPEHeaderHash SHA1  | [7400103f42e22809e66c207f1eb1d22cd947f22f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7400103f42e22809e66c207f1eb1d22cd947f22f) |
| RichPEHeaderHash SHA256| [7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a730b97ab977aa444fa261902822a905.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2009-09-05 11:27:16 |
| MD5                | [17c7bcae7ebabb95af2f7c91b19c361c](https://www.virustotal.com/gui/file/17c7bcae7ebabb95af2f7c91b19c361c) |
| SHA1               | [5ca6a52230507b1dffab7acd501540bc10f1ab81](https://www.virustotal.com/gui/file/5ca6a52230507b1dffab7acd501540bc10f1ab81) |
| SHA256             | [76940e313c27c7ff692051fbf1fbdec19c8c31a6723a9de7e15c3c1bec8186f6](https://www.virustotal.com/gui/file/76940e313c27c7ff692051fbf1fbdec19c8c31a6723a9de7e15c3c1bec8186f6) |
| Authentihash MD5   | [ccbb05849570b04ba210e45955d502ba](https://www.virustotal.com/gui/search/authentihash%253Accbb05849570b04ba210e45955d502ba) |
| Authentihash SHA1  | [eafd6be8f12ae5ce8aa3cd76f9f68ee69f4eb53c](https://www.virustotal.com/gui/search/authentihash%253Aeafd6be8f12ae5ce8aa3cd76f9f68ee69f4eb53c) |
| Authentihash SHA256| [4c80a2d3a0ef4ce0a3aec62e9d15b50679dec4cccb69a5c0b72529641ebfa5f4](https://www.virustotal.com/gui/search/authentihash%253A4c80a2d3a0ef4ce0a3aec62e9d15b50679dec4cccb69a5c0b72529641ebfa5f4) |
| RichPEHeaderHash MD5   | [eb7a6452e7d8e135bf9199524118601d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aeb7a6452e7d8e135bf9199524118601d) |
| RichPEHeaderHash SHA1  | [7400103f42e22809e66c207f1eb1d22cd947f22f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7400103f42e22809e66c207f1eb1d22cd947f22f) |
| RichPEHeaderHash SHA256| [7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/17c7bcae7ebabb95af2f7c91b19c361c.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2007-12-13 18:09:23 |
| MD5                | [7ffdd78d63ca7307a96843cfe806799e](https://www.virustotal.com/gui/file/7ffdd78d63ca7307a96843cfe806799e) |
| SHA1               | [64ff172bafc33f14ca5f2e35f9753d41e239a5e4](https://www.virustotal.com/gui/file/64ff172bafc33f14ca5f2e35f9753d41e239a5e4) |
| SHA256             | [8edab185e765f9806fa57153db1ede00e68270d2351443ee1de30674eca8d9b6](https://www.virustotal.com/gui/file/8edab185e765f9806fa57153db1ede00e68270d2351443ee1de30674eca8d9b6) |
| Authentihash MD5   | [d34ebed47db04efbe079e6656f917531](https://www.virustotal.com/gui/search/authentihash%253Ad34ebed47db04efbe079e6656f917531) |
| Authentihash SHA1  | [e54e9d578562719ca86461fec23bc9013cf8baa1](https://www.virustotal.com/gui/search/authentihash%253Ae54e9d578562719ca86461fec23bc9013cf8baa1) |
| Authentihash SHA256| [fa4be68f1ea1e36aca95fd62b6727cf9d22886c2612391faeb9c56a1c62c2ec9](https://www.virustotal.com/gui/search/authentihash%253Afa4be68f1ea1e36aca95fd62b6727cf9d22886c2612391faeb9c56a1c62c2ec9) |
| RichPEHeaderHash MD5   | [99e2fdbe346fb428297f8783591d5358](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A99e2fdbe346fb428297f8783591d5358) |
| RichPEHeaderHash SHA1  | [5eca02c6eaab32341e8baf724242ba04ac000d61](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A5eca02c6eaab32341e8baf724242ba04ac000d61) |
| RichPEHeaderHash SHA256| [684d8e76806e586f1dcf85eb846659993d1f0e5a20fc4a0dfdb4d0c6137bb55a](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A684d8e76806e586f1dcf85eb846659993d1f0e5a20fc4a0dfdb4d0c6137bb55a) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7ffdd78d63ca7307a96843cfe806799e.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-08-29 05:38:31 |
| MD5                | [192519661fe6d132f233d0355c3f4a6d](https://www.virustotal.com/gui/file/192519661fe6d132f233d0355c3f4a6d) |
| SHA1               | [adab368ed3c17b8f2dc0b2173076668b6153e03a](https://www.virustotal.com/gui/file/adab368ed3c17b8f2dc0b2173076668b6153e03a) |
| SHA256             | [90574d2c406b9738aae8fc629c3983c5e47a6282a43b052f38b5dd313380c30a](https://www.virustotal.com/gui/file/90574d2c406b9738aae8fc629c3983c5e47a6282a43b052f38b5dd313380c30a) |
| Authentihash MD5   | [464331a14dd967eed95bb16a8ccf6127](https://www.virustotal.com/gui/search/authentihash%253A464331a14dd967eed95bb16a8ccf6127) |
| Authentihash SHA1  | [8c0999041d3212be1510a766dcc8b7f4b2401fcf](https://www.virustotal.com/gui/search/authentihash%253A8c0999041d3212be1510a766dcc8b7f4b2401fcf) |
| Authentihash SHA256| [1126c9b043872383e5e0b1ac893ddf2238a2c130401627b259c81d98a3cefeae](https://www.virustotal.com/gui/search/authentihash%253A1126c9b043872383e5e0b1ac893ddf2238a2c130401627b259c81d98a3cefeae) |
| RichPEHeaderHash MD5   | [e93b5a02ff5f4c18b186ee8c35f3132e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae93b5a02ff5f4c18b186ee8c35f3132e) |
| RichPEHeaderHash SHA1  | [897dc8e1b30df0d168feda245816e72aa2cfcf9e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A897dc8e1b30df0d168feda245816e72aa2cfcf9e) |
| RichPEHeaderHash SHA256| [377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/192519661fe6d132f233d0355c3f4a6d.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* IoBuildDeviceIoControlRequest
* MmIsAddressValid
* IoDeleteSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* MmMapIoSpace
* RtlInitUnicodeString
* IofCallDriver
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* RtlFreeUnicodeString
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2004-10-13 15:37:45 |
| MD5                | [ab4656d1ec4d4cc83c76f639a5340e84](https://www.virustotal.com/gui/file/ab4656d1ec4d4cc83c76f639a5340e84) |
| SHA1               | [6f8b0e1c7d7bd7beed853e0d51ca03f143e5b703](https://www.virustotal.com/gui/file/6f8b0e1c7d7bd7beed853e0d51ca03f143e5b703) |
| SHA256             | [9917144b7240b1ce0cadb1210fd26182744fbbdf145943037c4b93e44aced207](https://www.virustotal.com/gui/file/9917144b7240b1ce0cadb1210fd26182744fbbdf145943037c4b93e44aced207) |
| Authentihash MD5   | [8eda3e023c5fcf652d9c703853699f4a](https://www.virustotal.com/gui/search/authentihash%253A8eda3e023c5fcf652d9c703853699f4a) |
| Authentihash SHA1  | [df5ec3bf96f7200f4365c383b0d93074a216324a](https://www.virustotal.com/gui/search/authentihash%253Adf5ec3bf96f7200f4365c383b0d93074a216324a) |
| Authentihash SHA256| [8c20d10857c37d8ed9151fa95f6bf12f99ef2c0bea36eed2370a1f4da7737951](https://www.virustotal.com/gui/search/authentihash%253A8c20d10857c37d8ed9151fa95f6bf12f99ef2c0bea36eed2370a1f4da7737951) |
| RichPEHeaderHash MD5   | [a22a9aa3f58912bffbd51273b848fa2a](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aa22a9aa3f58912bffbd51273b848fa2a) |
| RichPEHeaderHash SHA1  | [cf13386bd4c692fa4ee4873479f82e47a413cafc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Acf13386bd4c692fa4ee4873479f82e47a413cafc) |
| RichPEHeaderHash SHA256| [abc066632466728bf6828ac1dc4400fdfd0953bb97ad08f7eb27de3581f930e7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aabc066632466728bf6828ac1dc4400fdfd0953bb97ad08f7eb27de3581f930e7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ab4656d1ec4d4cc83c76f639a5340e84.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* MmUnmapIoSpace
* MmMapIoSpace
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .pdata
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2009-05-31 08:07:11 |
| MD5                | [b41dcdb2e710dffba2d8ea1defb0f087](https://www.virustotal.com/gui/file/b41dcdb2e710dffba2d8ea1defb0f087) |
| SHA1               | [11fcaeda49848474cee9989a00d8f29cb727acb7](https://www.virustotal.com/gui/file/11fcaeda49848474cee9989a00d8f29cb727acb7) |
| SHA256             | [a188760f1bf36584a2720014ca982252c6bcd824e7619a98580e28be6090dccc](https://www.virustotal.com/gui/file/a188760f1bf36584a2720014ca982252c6bcd824e7619a98580e28be6090dccc) |
| Authentihash MD5   | [80d3b21388e7b00c813d0c0cad450f6e](https://www.virustotal.com/gui/search/authentihash%253A80d3b21388e7b00c813d0c0cad450f6e) |
| Authentihash SHA1  | [413266463b3800a35c8fb3bda1dabe38e5ccd452](https://www.virustotal.com/gui/search/authentihash%253A413266463b3800a35c8fb3bda1dabe38e5ccd452) |
| Authentihash SHA256| [36d8d27d2ee91c45502d3a6688afc5c09b2b9776232074e65bd813a230eb37d1](https://www.virustotal.com/gui/search/authentihash%253A36d8d27d2ee91c45502d3a6688afc5c09b2b9776232074e65bd813a230eb37d1) |
| RichPEHeaderHash MD5   | [eb7a6452e7d8e135bf9199524118601d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aeb7a6452e7d8e135bf9199524118601d) |
| RichPEHeaderHash SHA1  | [7400103f42e22809e66c207f1eb1d22cd947f22f](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7400103f42e22809e66c207f1eb1d22cd947f22f) |
| RichPEHeaderHash SHA256| [7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A7efa73cf87c7b47175625395d918a9fcc93d9b5bf6392978613fced2155908fe) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b41dcdb2e710dffba2d8ea1defb0f087.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* KeBugCheckEx
* __C_specific_handler

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-02-17 11:47:03 |
| MD5                | [e99e86480d4206beb898dda82b71ca44](https://www.virustotal.com/gui/file/e99e86480d4206beb898dda82b71ca44) |
| SHA1               | [c41ff2067634a1cce6b8ec657cdfd87e7f6974e3](https://www.virustotal.com/gui/file/c41ff2067634a1cce6b8ec657cdfd87e7f6974e3) |
| SHA256             | [b074caef2fbf7e1dc8870edccb65254858d95836f466b4e9e6ca398bf7a27aa3](https://www.virustotal.com/gui/file/b074caef2fbf7e1dc8870edccb65254858d95836f466b4e9e6ca398bf7a27aa3) |
| Authentihash MD5   | [e80ddfe5a816dd6cb2ffd72da610d8db](https://www.virustotal.com/gui/search/authentihash%253Ae80ddfe5a816dd6cb2ffd72da610d8db) |
| Authentihash SHA1  | [a7e50663be8f7e859b63d1d266e8263a96f7520b](https://www.virustotal.com/gui/search/authentihash%253Aa7e50663be8f7e859b63d1d266e8263a96f7520b) |
| Authentihash SHA256| [f6e714528ad1b9eae72699078499735468140c1627e45f015762206ba7a77b47](https://www.virustotal.com/gui/search/authentihash%253Af6e714528ad1b9eae72699078499735468140c1627e45f015762206ba7a77b47) |
| RichPEHeaderHash MD5   | [510491d926769fc79a5d3287db0dd59d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A510491d926769fc79a5d3287db0dd59d) |
| RichPEHeaderHash SHA1  | [32af9e7e3a31bd44e3a5d717efcbe898d17c2423](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A32af9e7e3a31bd44e3a5d717efcbe898d17c2423) |
| RichPEHeaderHash SHA256| [8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e99e86480d4206beb898dda82b71ca44.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 01cc3af0c7b9f02c029c172f6f135621
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 735dfa995ca4af6545a694a22f0fb657  |
| ToBeSigned (TBS) SHA1             | 5957f3ae95e2a195cf0a1f99eeb989350b58f724 |
| ToBeSigned (TBS) SHA256           | 1278201f6ed95445add0bcdc6030e72609f88fa9bdabafb98615e358005025c1 |
| Subject                           | C=HU, ST=Budapest, L=Budapest, O=FinalWire, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=FinalWire |
| ValidFrom                         | 2010-07-29 00:00:00 |
| ValidTo                           | 2012-07-28 23:59:59 |
| Signature                         | 99e136ac112e7c78ce7c6227980b00b97242c5f7fd2e9b7759cd1e4eb323f0e4c36199f581121ce2ea9331fb4421f78feffdffbe83a0bab67a68a8ac5b3f79d7412b78ebed416feb9ab1d3412de204db326c47b2ab415938b7fadccc83ac35ed2cacbd29df428db05fabb874865fbeabf7eea6c6bd87c11292b2d48b8481cc02000ed147203fa6d9902796beba69ad8fef775205295d8537f50ca96b98ac9ccdf64391f07768979df2557742564bdc4a44e96673038495cbfac986dbf89311f445df1874534325f3b70262a9d9dc475cd9259e6dec576e50df06a7817a6033bdbe97c98d4684772864ecc564baa2356375fdf1e75982c96f4d7578a2d945e916 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01cc3af0c7b9f02c029c172f6f135621 |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* MmUnmapIoSpace
* IoCreateDevice
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* IofCallDriver
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeBugCheckEx
* RtlInitAnsiString
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2008-11-14 08:36:07 |
| MD5                | [3af19d325f9dcdf360276ae5e7c136ea](https://www.virustotal.com/gui/file/3af19d325f9dcdf360276ae5e7c136ea) |
| SHA1               | [9ec6f54c74bcc48e355226c26513a7240fd9462d](https://www.virustotal.com/gui/file/9ec6f54c74bcc48e355226c26513a7240fd9462d) |
| SHA256             | [b1e4455499c6a90ba9a861120a015a6b6f17e64479462b869ad0f05edf6552de](https://www.virustotal.com/gui/file/b1e4455499c6a90ba9a861120a015a6b6f17e64479462b869ad0f05edf6552de) |
| Authentihash MD5   | [d5f989cdc26ec4900dce75f37ae08922](https://www.virustotal.com/gui/search/authentihash%253Ad5f989cdc26ec4900dce75f37ae08922) |
| Authentihash SHA1  | [50c8857024e4bf57613d951932bbc3d890c839f6](https://www.virustotal.com/gui/search/authentihash%253A50c8857024e4bf57613d951932bbc3d890c839f6) |
| Authentihash SHA256| [9fa699246d83356d7b4bd99adf3c74f8e0682a650de2687075e70418ee9d5e38](https://www.virustotal.com/gui/search/authentihash%253A9fa699246d83356d7b4bd99adf3c74f8e0682a650de2687075e70418ee9d5e38) |
| RichPEHeaderHash MD5   | [2c53952789ebcf16a337a5ec3ab41667](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c53952789ebcf16a337a5ec3ab41667) |
| RichPEHeaderHash SHA1  | [60852524abfeefc666c143ac7a6d7350244e53be](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A60852524abfeefc666c143ac7a6d7350244e53be) |
| RichPEHeaderHash SHA256| [0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/3af19d325f9dcdf360276ae5e7c136ea.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2007-10-13 22:44:15 |
| MD5                | [4a829b8cf1f8fdb69e1d58ae04e6106e](https://www.virustotal.com/gui/file/4a829b8cf1f8fdb69e1d58ae04e6106e) |
| SHA1               | [43f53a739eda1e58f470e8e9ff9aa1437e5d9546](https://www.virustotal.com/gui/file/43f53a739eda1e58f470e8e9ff9aa1437e5d9546) |
| SHA256             | [bac7e75745d0cb8819de738b73edded02a07111587c4531383dccd4562922b65](https://www.virustotal.com/gui/file/bac7e75745d0cb8819de738b73edded02a07111587c4531383dccd4562922b65) |
| Authentihash MD5   | [40fbf3c682b7160db67000115f14c2d9](https://www.virustotal.com/gui/search/authentihash%253A40fbf3c682b7160db67000115f14c2d9) |
| Authentihash SHA1  | [c59bcd90cf7bf8999629bdf6f87dfe714d81ba2b](https://www.virustotal.com/gui/search/authentihash%253Ac59bcd90cf7bf8999629bdf6f87dfe714d81ba2b) |
| Authentihash SHA256| [9e855f9d5f5f4dc9420f34045df5d2c70498468f076d873571fc62e4015e38d3](https://www.virustotal.com/gui/search/authentihash%253A9e855f9d5f5f4dc9420f34045df5d2c70498468f076d873571fc62e4015e38d3) |
| RichPEHeaderHash MD5   | [99e2fdbe346fb428297f8783591d5358](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A99e2fdbe346fb428297f8783591d5358) |
| RichPEHeaderHash SHA1  | [5eca02c6eaab32341e8baf724242ba04ac000d61](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A5eca02c6eaab32341e8baf724242ba04ac000d61) |
| RichPEHeaderHash SHA256| [684d8e76806e586f1dcf85eb846659993d1f0e5a20fc4a0dfdb4d0c6137bb55a](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A684d8e76806e586f1dcf85eb846659993d1f0e5a20fc4a0dfdb4d0c6137bb55a) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/4a829b8cf1f8fdb69e1d58ae04e6106e.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2004-04-08 00:20:27 |
| MD5                | [8a212a246b3c41f3ddce5888aaaaacd6](https://www.virustotal.com/gui/file/8a212a246b3c41f3ddce5888aaaaacd6) |
| SHA1               | [1b25fbab2dbee5504dc94fbcc298cd8669c097a8](https://www.virustotal.com/gui/file/1b25fbab2dbee5504dc94fbcc298cd8669c097a8) |
| SHA256             | [bae4372a9284db52dedc1c1100cefa758b3ec8d9d4f0e5588a8db34ded5edb1f](https://www.virustotal.com/gui/file/bae4372a9284db52dedc1c1100cefa758b3ec8d9d4f0e5588a8db34ded5edb1f) |
| Authentihash MD5   | [8f76fc1f9d51c1d878961770de8468f3](https://www.virustotal.com/gui/search/authentihash%253A8f76fc1f9d51c1d878961770de8468f3) |
| Authentihash SHA1  | [7fcc190a9ea23e610a30db42d9a6d6fb174bd074](https://www.virustotal.com/gui/search/authentihash%253A7fcc190a9ea23e610a30db42d9a6d6fb174bd074) |
| Authentihash SHA256| [ac7cd788581d6f8098b5d438546eb3584c1b08dbe7fd3b1ddc2a7295bd4dd16f](https://www.virustotal.com/gui/search/authentihash%253Aac7cd788581d6f8098b5d438546eb3584c1b08dbe7fd3b1ddc2a7295bd4dd16f) |
| RichPEHeaderHash MD5   | [a22a9aa3f58912bffbd51273b848fa2a](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aa22a9aa3f58912bffbd51273b848fa2a) |
| RichPEHeaderHash SHA1  | [cf13386bd4c692fa4ee4873479f82e47a413cafc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Acf13386bd4c692fa4ee4873479f82e47a413cafc) |
| RichPEHeaderHash SHA256| [abc066632466728bf6828ac1dc4400fdfd0953bb97ad08f7eb27de3581f930e7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Aabc066632466728bf6828ac1dc4400fdfd0953bb97ad08f7eb27de3581f930e7) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8a212a246b3c41f3ddce5888aaaaacd6.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* MmUnmapIoSpace
* MmMapIoSpace
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

{{< /details >}}
#### Exported Functions
{{< details "Expand" >}}

{{< /details >}}

#### Sections
{{< details "Expand" >}}
* .text
* .rdata
* .pdata
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2008-12-13 11:32:27 |
| MD5                | [198b723e13a270bb664dcb9fb6ed42e6](https://www.virustotal.com/gui/file/198b723e13a270bb664dcb9fb6ed42e6) |
| SHA1               | [297fdf58e60d54bcddf2694c21ceb9da9ec17915](https://www.virustotal.com/gui/file/297fdf58e60d54bcddf2694c21ceb9da9ec17915) |
| SHA256             | [bd3cf8b9af255b5d4735782d3653be38578ff5be18846b13d05867a6159aaa53](https://www.virustotal.com/gui/file/bd3cf8b9af255b5d4735782d3653be38578ff5be18846b13d05867a6159aaa53) |
| Authentihash MD5   | [1022ba5d755ec9576fa590da85781481](https://www.virustotal.com/gui/search/authentihash%253A1022ba5d755ec9576fa590da85781481) |
| Authentihash SHA1  | [615360e669acdf516e8164b41d92f0d17ff1b1d7](https://www.virustotal.com/gui/search/authentihash%253A615360e669acdf516e8164b41d92f0d17ff1b1d7) |
| Authentihash SHA256| [56135fb8d5d3ed93b38679cb0dea9cc16ed7fdb0db9659e40a5c2d82655ada67](https://www.virustotal.com/gui/search/authentihash%253A56135fb8d5d3ed93b38679cb0dea9cc16ed7fdb0db9659e40a5c2d82655ada67) |
| RichPEHeaderHash MD5   | [2c53952789ebcf16a337a5ec3ab41667](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c53952789ebcf16a337a5ec3ab41667) |
| RichPEHeaderHash SHA1  | [60852524abfeefc666c143ac7a6d7350244e53be](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A60852524abfeefc666c143ac7a6d7350244e53be) |
| RichPEHeaderHash SHA256| [0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/198b723e13a270bb664dcb9fb6ed42e6.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IoBuildDeviceIoControlRequest
* IofCallDriver
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2006-06-24 06:26:46 |
| MD5                | [5bbe4e52bd33f1cdd4cf38c7c65f80ae](https://www.virustotal.com/gui/file/5bbe4e52bd33f1cdd4cf38c7c65f80ae) |
| SHA1               | [d11659145d6627f3d93975528d92fb6814171f91](https://www.virustotal.com/gui/file/d11659145d6627f3d93975528d92fb6814171f91) |
| SHA256             | [c6db7f2750e7438196ec906cc9eba540ef49ceca6dbd981038cef1dc50662a73](https://www.virustotal.com/gui/file/c6db7f2750e7438196ec906cc9eba540ef49ceca6dbd981038cef1dc50662a73) |
| Authentihash MD5   | [9291f8094b605eaaa503896f70750286](https://www.virustotal.com/gui/search/authentihash%253A9291f8094b605eaaa503896f70750286) |
| Authentihash SHA1  | [505b25bf6f81b9cd2aed9a4041c734619cca6f48](https://www.virustotal.com/gui/search/authentihash%253A505b25bf6f81b9cd2aed9a4041c734619cca6f48) |
| Authentihash SHA256| [db0bcfb5bbd93abc8682508af224a1aa5e96f82f037ee0ba26d1d02a3d639a2a](https://www.virustotal.com/gui/search/authentihash%253Adb0bcfb5bbd93abc8682508af224a1aa5e96f82f037ee0ba26d1d02a3d639a2a) |
| RichPEHeaderHash MD5   | [d8efbf77a16c80060c37681f4fc696d7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad8efbf77a16c80060c37681f4fc696d7) |
| RichPEHeaderHash SHA1  | [74f746e5eebab46d9ee2e15c96542fa508bdd271](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A74f746e5eebab46d9ee2e15c96542fa508bdd271) |
| RichPEHeaderHash SHA256| [c6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5bbe4e52bd33f1cdd4cf38c7c65f80ae.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlAssert
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2007-09-14 16:20:59 |
| MD5                | [25ede0fd525a30d31998ea62876961ec](https://www.virustotal.com/gui/file/25ede0fd525a30d31998ea62876961ec) |
| SHA1               | [f9cced7ccdc1f149ad8ad13a264c4425aee89b8e](https://www.virustotal.com/gui/file/f9cced7ccdc1f149ad8ad13a264c4425aee89b8e) |
| SHA256             | [cb59a641adb623a65a9b5af1db2ffd921fd1ca1bc046a6df85d5f2e00fd0b5a5](https://www.virustotal.com/gui/file/cb59a641adb623a65a9b5af1db2ffd921fd1ca1bc046a6df85d5f2e00fd0b5a5) |
| Authentihash MD5   | [697dd3d62bd8d00e89e5c107f3d1aa71](https://www.virustotal.com/gui/search/authentihash%253A697dd3d62bd8d00e89e5c107f3d1aa71) |
| Authentihash SHA1  | [9b4812dc3fc74f1dc144b916003e4341def44446](https://www.virustotal.com/gui/search/authentihash%253A9b4812dc3fc74f1dc144b916003e4341def44446) |
| Authentihash SHA256| [2e190b58266d9f7ce9681b834b0c7e6ab06e1305ab9258d714212a0bad58c0b4](https://www.virustotal.com/gui/search/authentihash%253A2e190b58266d9f7ce9681b834b0c7e6ab06e1305ab9258d714212a0bad58c0b4) |
| RichPEHeaderHash MD5   | [d7c3e34ff185cd060fd272724a9a08d4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad7c3e34ff185cd060fd272724a9a08d4) |
| RichPEHeaderHash SHA1  | [07bd4ac3ba36186190def09485c7e9ecdaae1d12](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A07bd4ac3ba36186190def09485c7e9ecdaae1d12) |
| RichPEHeaderHash SHA256| [e886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/25ede0fd525a30d31998ea62876961ec.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeEvent
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-10-05 02:21:07 |
| MD5                | [03ca3b1cff154ab8855043abadd07956](https://www.virustotal.com/gui/file/03ca3b1cff154ab8855043abadd07956) |
| SHA1               | [96047b280e0d6ddde9df1c79ca5f561219a0370d](https://www.virustotal.com/gui/file/96047b280e0d6ddde9df1c79ca5f561219a0370d) |
| SHA256             | [d330ab003206ce5e9828607562790aa8dd0453f6b7452f5c6053e3c6b6761d25](https://www.virustotal.com/gui/file/d330ab003206ce5e9828607562790aa8dd0453f6b7452f5c6053e3c6b6761d25) |
| Authentihash MD5   | [576743e8db31ee0e2dfb3731be4dc31c](https://www.virustotal.com/gui/search/authentihash%253A576743e8db31ee0e2dfb3731be4dc31c) |
| Authentihash SHA1  | [36ae0624e64979290cf6c643980aae899bb10311](https://www.virustotal.com/gui/search/authentihash%253A36ae0624e64979290cf6c643980aae899bb10311) |
| Authentihash SHA256| [8f69fa6128acbaa8217454ff22eb7fb9be1e841ed47116e7616749600b4bfc4d](https://www.virustotal.com/gui/search/authentihash%253A8f69fa6128acbaa8217454ff22eb7fb9be1e841ed47116e7616749600b4bfc4d) |
| RichPEHeaderHash MD5   | [e93b5a02ff5f4c18b186ee8c35f3132e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae93b5a02ff5f4c18b186ee8c35f3132e) |
| RichPEHeaderHash SHA1  | [897dc8e1b30df0d168feda245816e72aa2cfcf9e](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A897dc8e1b30df0d168feda245816e72aa2cfcf9e) |
| RichPEHeaderHash SHA256| [377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A377d1179f5eac38231f07ffef5b19a098956f1074a11f518bee00fee1f5f1cad) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/03ca3b1cff154ab8855043abadd07956.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 01cc3af0c7b9f02c029c172f6f135621
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 735dfa995ca4af6545a694a22f0fb657  |
| ToBeSigned (TBS) SHA1             | 5957f3ae95e2a195cf0a1f99eeb989350b58f724 |
| ToBeSigned (TBS) SHA256           | 1278201f6ed95445add0bcdc6030e72609f88fa9bdabafb98615e358005025c1 |
| Subject                           | C=HU, ST=Budapest, L=Budapest, O=FinalWire, OU=Digital ID Class 3 , Microsoft Software Validation v2, CN=FinalWire |
| ValidFrom                         | 2010-07-29 00:00:00 |
| ValidTo                           | 2012-07-28 23:59:59 |
| Signature                         | 99e136ac112e7c78ce7c6227980b00b97242c5f7fd2e9b7759cd1e4eb323f0e4c36199f581121ce2ea9331fb4421f78feffdffbe83a0bab67a68a8ac5b3f79d7412b78ebed416feb9ab1d3412de204db326c47b2ab415938b7fadccc83ac35ed2cacbd29df428db05fabb874865fbeabf7eea6c6bd87c11292b2d48b8481cc02000ed147203fa6d9902796beba69ad8fef775205295d8537f50ca96b98ac9ccdf64391f07768979df2557742564bdc4a44e96673038495cbfac986dbf89311f445df1874534325f3b70262a9d9dc475cd9259e6dec576e50df06a7817a6033bdbe97c98d4684772864ecc564baa2356375fdf1e75982c96f4d7578a2d945e916 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 01cc3af0c7b9f02c029c172f6f135621 |
| Version                           | 3 |
###### Certificate 655226e1b22e18e1590f2985ac22e75c
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 650704c342850095f3288eaf791147d4  |
| ToBeSigned (TBS) SHA1             | 4cdc38c800761463749c3cbd94a12f32e49877bf |
| ToBeSigned (TBS) SHA256           | 07b8f662558ec85b71b43a79c6e94698144f4ced2308af21e7ba1e5d461da214 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009,2 CA |
| ValidFrom                         | 2009-05-21 00:00:00 |
| ValidTo                           | 2019-05-20 23:59:59 |
| Signature                         | 8b03c0dd94d841a26169b015a878c730c6903c7e42f724b6e4837317047f04109ca1e2fa812febc0ca44e772e050b6551020836e9692e49a516ab43731dca52deb8c00c71d4fe74d32ba85f84ebefa675565f06abe7aca64381a101078457631f3867a030f60c2b35d9df68b6676821b59e183e5bd49a53856e5de41770e580f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 655226e1b22e18e1590f2985ac22e75c |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* IoBuildDeviceIoControlRequest
* MmIsAddressValid
* IoDeleteSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* MmMapIoSpace
* RtlInitUnicodeString
* IofCallDriver
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* MmBuildMdlForNonPagedPool
* RtlFreeUnicodeString
* KeBugCheckEx
* IoGetDeviceObjectPointer
* IoAllocateMdl
* MmMapLockedPagesSpecifyCache
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2007-07-09 18:15:14 |
| MD5                | [2b6a17ec50d3a21e030ed78f7acbd2af](https://www.virustotal.com/gui/file/2b6a17ec50d3a21e030ed78f7acbd2af) |
| SHA1               | [cd7b0c6b6ef809e7fb1f68ba36150eceabe500f7](https://www.virustotal.com/gui/file/cd7b0c6b6ef809e7fb1f68ba36150eceabe500f7) |
| SHA256             | [d3b5fd13a53eee5c468c8bfde4bfa7b968c761f9b781bb80ccd5637ee052ee7d](https://www.virustotal.com/gui/file/d3b5fd13a53eee5c468c8bfde4bfa7b968c761f9b781bb80ccd5637ee052ee7d) |
| Authentihash MD5   | [d9faacfcccaa55e240ae3967dba2ccc6](https://www.virustotal.com/gui/search/authentihash%253Ad9faacfcccaa55e240ae3967dba2ccc6) |
| Authentihash SHA1  | [d4933bd439b26de02e70e2001913b0bced6b5754](https://www.virustotal.com/gui/search/authentihash%253Ad4933bd439b26de02e70e2001913b0bced6b5754) |
| Authentihash SHA256| [93cdc6e885459d95d5e9d6b2ee979e5cad44af1f57bca3947d594847cfbd5829](https://www.virustotal.com/gui/search/authentihash%253A93cdc6e885459d95d5e9d6b2ee979e5cad44af1f57bca3947d594847cfbd5829) |
| RichPEHeaderHash MD5   | [d7c3e34ff185cd060fd272724a9a08d4](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad7c3e34ff185cd060fd272724a9a08d4) |
| RichPEHeaderHash SHA1  | [07bd4ac3ba36186190def09485c7e9ecdaae1d12](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A07bd4ac3ba36186190def09485c7e9ecdaae1d12) |
| RichPEHeaderHash SHA256| [e886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ae886be3aa324ce0db073d3bfc7e1603fdfa353e31159343409d6a3117c5e7849) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2b6a17ec50d3a21e030ed78f7acbd2af.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2009-10-09 14:49:06 |
| MD5                | [2d854c6772f0daa8d1fde4168d26c36b](https://www.virustotal.com/gui/file/2d854c6772f0daa8d1fde4168d26c36b) |
| SHA1               | [0b3836d5d98bc8862a380aae19caa3e77a2d93ef](https://www.virustotal.com/gui/file/0b3836d5d98bc8862a380aae19caa3e77a2d93ef) |
| SHA256             | [db0d425708ba908aedf5f8762d6fdca7636ae3a537372889446176c0237a2836](https://www.virustotal.com/gui/file/db0d425708ba908aedf5f8762d6fdca7636ae3a537372889446176c0237a2836) |
| Authentihash MD5   | [3e15e42c2c1383d31e85b2da63dd7823](https://www.virustotal.com/gui/search/authentihash%253A3e15e42c2c1383d31e85b2da63dd7823) |
| Authentihash SHA1  | [bd280953877c65eea79de5a3edc1961b650e7c76](https://www.virustotal.com/gui/search/authentihash%253Abd280953877c65eea79de5a3edc1961b650e7c76) |
| Authentihash SHA256| [d9674a1364fde6b5e7fb1770bdebb8db7de8e15f3c976e5c5102775c95452967](https://www.virustotal.com/gui/search/authentihash%253Ad9674a1364fde6b5e7fb1770bdebb8db7de8e15f3c976e5c5102775c95452967) |
| RichPEHeaderHash MD5   | [510491d926769fc79a5d3287db0dd59d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A510491d926769fc79a5d3287db0dd59d) |
| RichPEHeaderHash SHA1  | [32af9e7e3a31bd44e3a5d717efcbe898d17c2423](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A32af9e7e3a31bd44e3a5d717efcbe898d17c2423) |
| RichPEHeaderHash SHA256| [8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2d854c6772f0daa8d1fde4168d26c36b.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* MmUnmapIoSpace
* IoCreateDevice
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* IofCallDriver
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeBugCheckEx
* RtlInitAnsiString
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2008-08-29 08:41:55 |
| MD5                | [1ad400766530669d14a077514599e7f3](https://www.virustotal.com/gui/file/1ad400766530669d14a077514599e7f3) |
| SHA1               | [1b84abffd814b9f4595296b3e5ede0c44e630967](https://www.virustotal.com/gui/file/1b84abffd814b9f4595296b3e5ede0c44e630967) |
| SHA256             | [dfe57c6a4ef4d2491be325d67428698a61d9c5d2a24dbada10043d313be2c8cc](https://www.virustotal.com/gui/file/dfe57c6a4ef4d2491be325d67428698a61d9c5d2a24dbada10043d313be2c8cc) |
| Authentihash MD5   | [63fb6eee97dd766aceb02f08b55cbc3a](https://www.virustotal.com/gui/search/authentihash%253A63fb6eee97dd766aceb02f08b55cbc3a) |
| Authentihash SHA1  | [0d67d6c7eb3dc1555faad8b09b60d03e3ec10d6d](https://www.virustotal.com/gui/search/authentihash%253A0d67d6c7eb3dc1555faad8b09b60d03e3ec10d6d) |
| Authentihash SHA256| [fe9c104a3bb9184a8f792f3f8a3e90d83b9f19cf83cd93d116b02e17f54d727d](https://www.virustotal.com/gui/search/authentihash%253Afe9c104a3bb9184a8f792f3f8a3e90d83b9f19cf83cd93d116b02e17f54d727d) |
| RichPEHeaderHash MD5   | [2c53952789ebcf16a337a5ec3ab41667](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A2c53952789ebcf16a337a5ec3ab41667) |
| RichPEHeaderHash SHA1  | [60852524abfeefc666c143ac7a6d7350244e53be](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A60852524abfeefc666c143ac7a6d7350244e53be) |
| RichPEHeaderHash SHA256| [0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A0a1214a3de635359675999b347fd34869caf91a1cd0510677996adcec5c2c6bc) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1ad400766530669d14a077514599e7f3.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 1b417ba2cdab8010ecfc5ad9dd4baf33
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 32ff43e593925e5eab372e2d5e3c9734  |
| ToBeSigned (TBS) SHA1             | 405c78a239f39963fe8aa5ff5283c582aa369e7b |
| ToBeSigned (TBS) SHA256           | 0a6e66dd63e42179cd9e1a1c9d22decad3abe55cfa6fa4062f5c503742d2076f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2006-10-18 00:00:00 |
| ValidTo                           | 2008-10-17 23:59:59 |
| Signature                         | 5e0e77e4e5de0c6c4b7822b17a1e8ebd0960806438f5073c686b575f60dd4129d66bd66b7e4f33cff39dc890ae077db68615ad8d431eec3bf1531f6eb505fe48d186df3306d27893b42af5ef264b621acf26475fe93dd00906f61c78425c101d268d1050db3f7264d5e4a75a205b488684b716f3f2b317367ed13f34553238f6b4ab7a98c9fe48d32289d528d8db8cb583cef299e53f2fdde6d84ae2d2fd41cb826973c3da647221d9efbb2383cdae5c52adfa407399ebd2b9fafbf5c6246f944cd8e9ed79b4540b8ec53ba603464ae42f09468f762f71ddf9068cdd869c6fcf2d3806c6d20ab9781ee027849d946c5d2f58d7853bda919ca412e0c20024a6b7 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 1b417ba2cdab8010ecfc5ad9dd4baf33 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* IoCreateDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeInitializeEvent
* RtlInitAnsiString
* MmUnmapIoSpace
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
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
* INIT

{{< /details >}}
#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2005-12-15 17:15:51 |
| MD5                | [0ec31f45e2e698a83131b4443f9a6dd7](https://www.virustotal.com/gui/file/0ec31f45e2e698a83131b4443f9a6dd7) |
| SHA1               | [d43b2ac1221f2eaf2c170788280255cfef3edd72](https://www.virustotal.com/gui/file/d43b2ac1221f2eaf2c170788280255cfef3edd72) |
| SHA256             | [e8b51ab681714e491ab1a59a7c9419db39db04b0dd7be11293f3a0951afe740e](https://www.virustotal.com/gui/file/e8b51ab681714e491ab1a59a7c9419db39db04b0dd7be11293f3a0951afe740e) |
| Authentihash MD5   | [5305c2315974896cd8e5897aa05f2df6](https://www.virustotal.com/gui/search/authentihash%253A5305c2315974896cd8e5897aa05f2df6) |
| Authentihash SHA1  | [fad47f27c9498b1c1db11c0d0edfdb486d700971](https://www.virustotal.com/gui/search/authentihash%253Afad47f27c9498b1c1db11c0d0edfdb486d700971) |
| Authentihash SHA256| [bb11fe81a2d2ca868398055e9f8cc7349ff4ac6d0a4f1e85e7e5d04ed7357349](https://www.virustotal.com/gui/search/authentihash%253Abb11fe81a2d2ca868398055e9f8cc7349ff4ac6d0a4f1e85e7e5d04ed7357349) |
| RichPEHeaderHash MD5   | [d8efbf77a16c80060c37681f4fc696d7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad8efbf77a16c80060c37681f4fc696d7) |
| RichPEHeaderHash SHA1  | [74f746e5eebab46d9ee2e15c96542fa508bdd271](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A74f746e5eebab46d9ee2e15c96542fa508bdd271) |
| RichPEHeaderHash SHA256| [c6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ec31f45e2e698a83131b4443f9a6dd7.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlAssert
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2010-01-09 15:48:06 |
| MD5                | [96fb2101f85fa81871256107bdd25169](https://www.virustotal.com/gui/file/96fb2101f85fa81871256107bdd25169) |
| SHA1               | [ba63502aaf8c5a7c2464e83295948447e938a844](https://www.virustotal.com/gui/file/ba63502aaf8c5a7c2464e83295948447e938a844) |
| SHA256             | [e9919d1546c7dfef62ff01b87f739812de0a57463611c12012013ae689023ce1](https://www.virustotal.com/gui/file/e9919d1546c7dfef62ff01b87f739812de0a57463611c12012013ae689023ce1) |
| Authentihash MD5   | [0beb615ff472de5c798f64ddf2abb8ea](https://www.virustotal.com/gui/search/authentihash%253A0beb615ff472de5c798f64ddf2abb8ea) |
| Authentihash SHA1  | [eb54c8926bdb26a17e195d13839b7d250451c66e](https://www.virustotal.com/gui/search/authentihash%253Aeb54c8926bdb26a17e195d13839b7d250451c66e) |
| Authentihash SHA256| [6f3a182bbeba28dd15e1ad52041b8b32670651686697224cad821a334a8600da](https://www.virustotal.com/gui/search/authentihash%253A6f3a182bbeba28dd15e1ad52041b8b32670651686697224cad821a334a8600da) |
| RichPEHeaderHash MD5   | [510491d926769fc79a5d3287db0dd59d](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A510491d926769fc79a5d3287db0dd59d) |
| RichPEHeaderHash SHA1  | [32af9e7e3a31bd44e3a5d717efcbe898d17c2423](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A32af9e7e3a31bd44e3a5d717efcbe898d17c2423) |
| RichPEHeaderHash SHA256| [8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8f0295454ac4eec12c5329539ee515da9c074bf6d009cc0b54ad4506d4097389) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/96fb2101f85fa81871256107bdd25169.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3825d7faf861af9ef490e726b5d65ad5
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | d6c7684e9aaa508cf268335f83afe040  |
| ToBeSigned (TBS) SHA1             | 18066d20ad92409c567cdfde745279ff71c75226 |
| ToBeSigned (TBS) SHA256           | a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2 |
| ValidFrom                         | 2007-06-15 00:00:00 |
| ValidTo                           | 2012-06-14 23:59:59 |
| Signature                         | 50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3825d7faf861af9ef490e726b5d65ad5 |
| Version                           | 3 |
###### Certificate 47bf1995df8d524643f7db6d480d31a4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 518d2ea8a21e879c942d504824ac211c  |
| ToBeSigned (TBS) SHA1             | 21ce87d827077e61abddf2beba69fde5432ea031 |
| ToBeSigned (TBS) SHA256           | 1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7 |
| Subject                           | C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA |
| ValidFrom                         | 2003-12-04 00:00:00 |
| ValidTo                           | 2013-12-03 23:59:59 |
| Signature                         | 4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 47bf1995df8d524643f7db6d480d31a4 |
| Version                           | 3 |
###### Certificate 4191a15a3978dfcf496566381d4c75c2
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 41011f8d0e7c7a6408334ca387914c61  |
| ToBeSigned (TBS) SHA1             | c7fc1727f5b75a6421a1f95c73bbdb23580c48e5 |
| ToBeSigned (TBS) SHA256           | 88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0 |
| Subject                           | C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA |
| ValidFrom                         | 2004-07-16 00:00:00 |
| ValidTo                           | 2014-07-15 23:59:59 |
| Signature                         | ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 4191a15a3978dfcf496566381d4c75c2 |
| Version                           | 3 |
###### Certificate 739a73c1864ae27d7d9cdcf7055888e4
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4ccfe1bafb291fc51e5636295c8e38eb  |
| ToBeSigned (TBS) SHA1             | c93bdd8fd964b6c750fcad1455a37fdd77276446 |
| ToBeSigned (TBS) SHA256           | 63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f |
| Subject                           | C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS |
| ValidFrom                         | 2008-09-04 00:00:00 |
| ValidTo                           | 2010-10-17 23:59:59 |
| Signature                         | 6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.5 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 739a73c1864ae27d7d9cdcf7055888e4 |
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

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlFreeUnicodeString
* IoGetDeviceObjectPointer
* MmMapIoSpace
* IofCompleteRequest
* KeWaitForSingleObject
* PsGetVersion
* IoCreateSymbolicLink
* MmIsAddressValid
* ObfDereferenceObject
* MmUnmapIoSpace
* IoCreateDevice
* IoDeleteSymbolicLink
* RtlAnsiStringToUnicodeString
* IofCallDriver
* RtlInitUnicodeString
* IoDeleteDevice
* strchr
* KeBugCheckEx
* RtlInitAnsiString
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* __C_specific_handler
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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2006-01-14 09:24:35 |
| MD5                | [b3d6378185356326fd8ee4329b0b7698](https://www.virustotal.com/gui/file/b3d6378185356326fd8ee4329b0b7698) |
| SHA1               | [f7330a6a4d9df2f35ab93a28c8ee1eb14a74be6e](https://www.virustotal.com/gui/file/f7330a6a4d9df2f35ab93a28c8ee1eb14a74be6e) |
| SHA256             | [f13f6a4bf7711216c9e911f18dfa2735222551fb1f8c1a645a8674c1983ccea6](https://www.virustotal.com/gui/file/f13f6a4bf7711216c9e911f18dfa2735222551fb1f8c1a645a8674c1983ccea6) |
| Authentihash MD5   | [94ce9ab807de36019621677807e36b34](https://www.virustotal.com/gui/search/authentihash%253A94ce9ab807de36019621677807e36b34) |
| Authentihash SHA1  | [d9673daa57dd14ec8cddae4212c94d27f9eba4a0](https://www.virustotal.com/gui/search/authentihash%253Ad9673daa57dd14ec8cddae4212c94d27f9eba4a0) |
| Authentihash SHA256| [40ebdd21c93146a92536688a230801791a86e2bec2719896a3d629ad930e9f17](https://www.virustotal.com/gui/search/authentihash%253A40ebdd21c93146a92536688a230801791a86e2bec2719896a3d629ad930e9f17) |
| RichPEHeaderHash MD5   | [d8efbf77a16c80060c37681f4fc696d7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad8efbf77a16c80060c37681f4fc696d7) |
| RichPEHeaderHash SHA1  | [74f746e5eebab46d9ee2e15c96542fa508bdd271](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A74f746e5eebab46d9ee2e15c96542fa508bdd271) |
| RichPEHeaderHash SHA256| [c6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b3d6378185356326fd8ee4329b0b7698.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlAssert
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
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
| Creation Timestamp           | 2006-08-09 16:44:56 |
| MD5                | [0c7f66cd219817eaab41f36d4bc0d4cd](https://www.virustotal.com/gui/file/0c7f66cd219817eaab41f36d4bc0d4cd) |
| SHA1               | [9d0b824892fbfb0b943911326f95cd0264c60f7d](https://www.virustotal.com/gui/file/9d0b824892fbfb0b943911326f95cd0264c60f7d) |
| SHA256             | [f64a78b1294e6837f12f171a663d8831f232b1012fd8bae3c2c6368fbf71219b](https://www.virustotal.com/gui/file/f64a78b1294e6837f12f171a663d8831f232b1012fd8bae3c2c6368fbf71219b) |
| Authentihash MD5   | [67d8349af99121fe4b2029c3772f0807](https://www.virustotal.com/gui/search/authentihash%253A67d8349af99121fe4b2029c3772f0807) |
| Authentihash SHA1  | [add7ea044995f5f6b9cc9403fd30a8124a9ff158](https://www.virustotal.com/gui/search/authentihash%253Aadd7ea044995f5f6b9cc9403fd30a8124a9ff158) |
| Authentihash SHA256| [23440de2db935be1c06b40ff2809215d00d95930abe3fda70ea57cf8a9fc0e98](https://www.virustotal.com/gui/search/authentihash%253A23440de2db935be1c06b40ff2809215d00d95930abe3fda70ea57cf8a9fc0e98) |
| RichPEHeaderHash MD5   | [d8efbf77a16c80060c37681f4fc696d7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ad8efbf77a16c80060c37681f4fc696d7) |
| RichPEHeaderHash SHA1  | [74f746e5eebab46d9ee2e15c96542fa508bdd271](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A74f746e5eebab46d9ee2e15c96542fa508bdd271) |
| RichPEHeaderHash SHA256| [c6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c](https://www.virustotal.com/gui/search/rich_pe_header_hash%253Ac6e67d594fc9ff3077181314e987207660ae9627e0ec3ed7f8ad96e7719c130c) |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0c7f66cd219817eaab41f36d4bc0d4cd.bin" "Download" >}} 


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* RtlAssert
* MmUnmapIoSpace
* MmMapIoSpace
* IofCompleteRequest
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice

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
      "IsCertificateAuthority": false,
      "SerialNumber": "3825d7faf861af9ef490e726b5d65ad5",
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "TBS": {
        "MD5": "d6c7684e9aaa508cf268335f83afe040",
        "SHA1": "18066d20ad92409c567cdfde745279ff71c75226",
        "SHA256": "a612fb22ce8be6dab75e47c98508f98496583e79c9c97b936a8caee9ea9f3fff",
        "SHA384": "35c249d6ad0261a6229b2a727067ac6ba32a5d24b30b9249051f748c7735fbe2ec2ef26a702c50df1790fbe32a65aee7"
      },
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "47bf1995df8d524643f7db6d480d31a4",
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "TBS": {
        "MD5": "518d2ea8a21e879c942d504824ac211c",
        "SHA1": "21ce87d827077e61abddf2beba69fde5432ea031",
        "SHA256": "1ec3b4f02e03930a470020e0e48d24b84678bb558f46182888d870541f5e25c7",
        "SHA384": "53e346bbde23779a5d116cc9d86fdd71c97b1f1b343439f8a11aa1d3c87af63864bb8488a5aeb2d0c26a6a1e0b15f03f"
      },
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": true,
      "SerialNumber": "4191a15a3978dfcf496566381d4c75c2",
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "TBS": {
        "MD5": "41011f8d0e7c7a6408334ca387914c61",
        "SHA1": "c7fc1727f5b75a6421a1f95c73bbdb23580c48e5",
        "SHA256": "88dd3952638ee82738c03168e6fd863fe4eab1059ee5e2926ad8cb587c255dc0",
        "SHA384": "a00aa5ed457c41e37967882644d63366bae014f03a986576d8514164d7027acf7d0b5e03d764db2558f60db148954459"
      },
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59",
      "Version": 3
    },
    {
      "IsCertificateAuthority": false,
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Signature": "6cd0fe216b27c908f3d444ef0428c76bbc25f74beb7f2027a497499ea5b5c61f99c4e455341bdab5f26b3cc920a9e8224eb79a95ebb81e3fef374f992255d7a997e43f5b497be9bbfe7d28c6791d0e2c93e72668d8c18e08f3329dde27f8a587a59202d9ff6db84fbb56ea4d37b702d80ef4fcdc49bc636351e3ab2043db01b4312c653e830819cf8c44ce3da714dc73933f242b035ef6ef8dc486b5a8aece6e4061138a7e2f6916d527b5a3a6cfeb6475cba7b0afa08a5b6e8590e02758428b217a288d29f641cd493f34f251739b8b529fe0d30182ad5f4fb461caf7f6447598bc5b6833fb8be5884ee329413c4550c8715929c6767bb0fa5c101de989f5ee",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=CA, ST=Quebec, L=Laval, O=LAVALYS, OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=Software Licensing Department, CN=LAVALYS",
      "TBS": {
        "MD5": "4ccfe1bafb291fc51e5636295c8e38eb",
        "SHA1": "c93bdd8fd964b6c750fcad1455a37fdd77276446",
        "SHA256": "63b214b64cb75b53fd0d4baacbcadee892160af685a79f6b5c6f984214521c8f",
        "SHA384": "70411e706a18564522cdcc92bbdaf6187c2a318b8beb2e7025959e04475e8a5bbdea470a6d82109c0fbd7b56b22abf5f"
      },
      "ValidFrom": "2008-09-04 00:00:00",
      "ValidTo": "2010-10-17 23:59:59",
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
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "739a73c1864ae27d7d9cdcf7055888e4",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/3aa6e630-59be-4a15-a30c-aaed4c1edaf0.yaml)

*last_updated:* 2025-03-03

{{< /column >}}
{{< /block >}}
