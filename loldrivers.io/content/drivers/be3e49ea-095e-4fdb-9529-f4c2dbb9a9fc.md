+++

description = ""
title = "be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc"
weight = 10
displayTitle = "PhlashNT.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# PhlashNT.sys ![:inline](/images/twitter_verified.png) 


### Description

PhlashNT.sys is a vulnerable driver and more information will be added as found.
- **UUID**: be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/e9e786bdba458b8b4f9e93d034f73d00.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create PhlashNT.sys binPath=C:\windows\temp\PhlashNT.sys type=kernel &amp;&amp; sc.exe start PhlashNT.sys
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

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara/yara-rules_vuln_strict_renamed.yar" "Renamed" >}}{{< tip >}}for renamed driver files{{< /tip >}} 


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

{{< button "https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon_config_vulnerable_hashes.xml" "Alert" >}}{{< tip >}}on hashes{{< /tip >}} 

{{< /details >}}

{{< /column >}}
{{< /block >}}


### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | PhlashNT.sys |
| MD5                | [e9e786bdba458b8b4f9e93d034f73d00](https://www.virustotal.com/gui/file/e9e786bdba458b8b4f9e93d034f73d00) |
| SHA1               | [c6d349823bbb1f5b44bae91357895dba653c5861](https://www.virustotal.com/gui/file/c6d349823bbb1f5b44bae91357895dba653c5861) |
| SHA256             | [65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890](https://www.virustotal.com/gui/file/65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890) |
| Authentihash MD5   | [5cf72ecb15ffea87586783893b02c43d](https://www.virustotal.com/gui/search/authentihash%253A5cf72ecb15ffea87586783893b02c43d) |
| Authentihash SHA1  | [ef2d7210b761f158a0832083a8407b3ec2f99db9](https://www.virustotal.com/gui/search/authentihash%253Aef2d7210b761f158a0832083a8407b3ec2f99db9) |
| Authentihash SHA256| [cde02c7db90626bcfbfbbc1315d4ce18d4f15667fa57c16b9ac2b060507c62ad](https://www.virustotal.com/gui/search/authentihash%253Acde02c7db90626bcfbfbbc1315d4ce18d4f15667fa57c16b9ac2b060507c62ad) |
| Company           | Phoenix Technologies, Ltd. |
| Description       | SWinFlash Driver for Windows NT |
| Product           | WinPhlash |
| OriginalFilename  | PHLASHNT.SYS |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* IoDeleteSymbolicLink
* IofCompleteRequest
* MmMapLockedPages
* RtlAssert
* DbgPrint
* MmMapIoSpace
* MmUnmapIoSpace
* ExFreePoolWithTag
* ExAllocatePoolWithTag

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}

#### Signature
{{< details "Expand" >}}
```
{
  "Certificates": [
    {
      "Signature": "50c54bc82480dfe40d24c2de1ab1a102a1a6822d0c831581370a820e2cb05a1761b5d805fe88dbf19191b3561a40a6eb92be3839b07536743a984fe437ba9989ca95421db0b9c7a08d57e0fad5640442354e01d133a217c84daa27c7f2e1864c02384d8378c6fc53e0ebe00687dda4969e5e0c98e2a5bebf8285c360e1dfad28d8c7a54b64dac71b5bbdac3908d53822a1338b2f8a9aebbc07213f44410907b5651c24bc48d34480eba1cfc902b414cf54c716a3805cf9793e5d727d88179e2c43a2ca53ce7d3df62a3ab84f9400a56d0a835df95e53f418b3570f70c3fbf5ad95a00e17dec4168060c90f2b6e8604f1ebf47827d105c5ee345b5eb94932f233",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services Signer , G2",
      "ValidFrom": "2007-06-15 00:00:00",
      "ValidTo": "2012-06-14 23:59:59"
    },
    {
      "Signature": "4a6bf9ea58c2441c318979992b96bf82ac01d61c4ccdb08a586edf0829a35ec8ca9313e704520def47272f0038b0e4c9934e9ad4226215f73f37214f703180f18b3887b3e8e89700fecf55964e24d2a9274e7aaeb76141f32acee7c9d95eddbb2b853eb59db5d9e157ffbeb4c57ef5cf0c9ef097fe2bd33b521b1b3827f73f4a",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., CN=VeriSign Time Stamping Services CA",
      "ValidFrom": "2003-12-04 00:00:00",
      "ValidTo": "2013-12-03 23:59:59"
    },
    {
      "Signature": "ae3a17b84a7b55fa6455ec40a4ed494190999c89bcaf2e1dca7823f91c190f7feb68bc32d98838dedc3fd389b43fb18296f1a45abaed2e26d3de7c016e000a00a4069211480940f91c1879672324e0bbd5e150ae1bf50edde02e81cd80a36c524f9175558aba22f2d2ea4175882f63557d1e545a9559cad93481c05f5ef67ab5",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "ValidFrom": "2004-07-16 00:00:00",
      "ValidTo": "2014-07-15 23:59:59"
    },
    {
      "Signature": "01e446b33b457f7513877e5f43de468ecb8abdb64741bccccc7491d8ce395195a4a6b547c0efd2da7b8f5711f4328c7ccd3fee42da04214af7c843884a6f5cca14fc4bd19f4cbdd4556ecc02be0da6888f8609baa425bde8b0f0fa8b714e67b0cb82a8d78e55f737ebf03e88efe4e08afd1c6e2e61414875b4b02c1d28d8490fd715f02473253ccc880cde284c6554fe5eae8cea19ad2c51b29b3a47f53c80350117e24987d6544afb4bab07bcbf7d79cfbf35005cbb9ecffc82891b39a05197b6dec0b307ff449644c0342a195cabeef03bec294eb513c537857e75d5b4d60d066eb5d26c237167eaf1718eaf4e74aa0cf9ecbf4c58fa5e909b6d39cb86883f8b1ca81632d5fe6db9f1f8b3ead791f6364778c0272a15c768d6f4c5fc4f4ec8673f102d409ff11ec96148e7a703fc31730cf04688fe56da492995ef09daa3e5beef60ecd954a0599c28bd54ef66157f874c84dba60e95672e517b3439b641c28c846826dc240209e7818e0a972defeea7b998a60f818dc710b5e1ed982f486f53854964789bec5dac970b5526c3efba8dc8d1a52f5a7f936b611a339b18b8a26210de24ea76e12f43ebecdd7c12342489da2855aee5754e312b6763b6a8d7ab730a03cec5ea593fc7eb2a45aea8625b2f009939abb45f73c308ec80118f470e8f2a1343e191066255bbffba3da9a93d260faeca7d628b155589d694344dd665",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority",
      "ValidFrom": "2006-05-23 17:01:29",
      "ValidTo": "2016-05-23 17:11:29"
    },
    {
      "Signature": "addfb0156ef6ad5c431dffc5ef41cefa457136306d15d84146668cbe5be0f54450614be60c40f7b9ecf7b16b10fe5bcaeff5e31433abd8e218e5cfac8ecb246b3d59d8b3aa0b5ae88feab0b12dd24dc2f4cb51fec3a2a302f67903a652d52197b07e77410d4e480d0f2c3003e150f5da93bd09c91977fbc8d7652f4f5bb7c06d672dbda83f7458f6cb52719cd7f393395e1b036a9701608eccb8c1d2f42ccbee6e53e5fc342b9d5b65aac07d35b2d3b69fb8f51184699a46ac6d3ce7de8fa73353f74f58572f5d982d0d56ce29321d35633de97a04f99d73969c4c0b3bce7cdb95ec67c0b78deee1c5af17e49e9d4978db7f4063c9670adf5094c3e5a730d4fe",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, ST=California, L=Milpitas, O=Phoenix Technology Ltd., OU=Digital ID Class 3 , Microsoft Software Validation v2, OU=CSS Core Features Development, CN=Phoenix Technology Ltd.",
      "ValidFrom": "2008-11-14 00:00:00",
      "ValidTo": "2009-11-14 23:59:59"
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)04, CN=VeriSign Class 3 Code Signing 2004 CA",
      "SerialNumber": "55272d7780471b989f3def09bb221c53"
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc.yaml)

*last_updated:* 2023-06-21








{{< /column >}}
{{< /block >}}
