+++

description = ""
title = "2ea12acc-95b6-4f91-afb7-8ded7a2fe9d9"
weight = 10
displayTitle = "vmdrv.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vmdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

vmdrv.sys is a vulnerable driver and more information will be added as found.
- **UUID**: 2ea12acc-95b6-4f91-afb7-8ded7a2fe9d9
- **Created**: 2023-05-06
- **Author**: Nasreddine Bencherchali
- **Acknowledgement**: [] | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/6d67da13cf84f15f6797ed929dd8cf5d.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create vmdrv.sys binPath=C:\windows\temp\vmdrv.sys type=kernel &amp;&amp; sc.exe start vmdrv.sys
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
<li><a href="Internal Research">Internal Research</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | vmdrv.sys |
| MD5                | [6d67da13cf84f15f6797ed929dd8cf5d](https://www.virustotal.com/gui/file/6d67da13cf84f15f6797ed929dd8cf5d) |
| SHA1               | [1a17cc64e47d3db7085a4dc365049a2d4552dc8a](https://www.virustotal.com/gui/file/1a17cc64e47d3db7085a4dc365049a2d4552dc8a) |
| SHA256             | [5c0b429e5935814457934fa9c10ac7a88e19068fa1bd152879e4e9b89c103921](https://www.virustotal.com/gui/file/5c0b429e5935814457934fa9c10ac7a88e19068fa1bd152879e4e9b89c103921) |
| Authentihash MD5   | [9ee5190f4bd124445626451cc09d49ce](https://www.virustotal.com/gui/search/authentihash%253A9ee5190f4bd124445626451cc09d49ce) |
| Authentihash SHA1  | [b73a1aae1e15b9a7e2cc0d486449e132671aebec](https://www.virustotal.com/gui/search/authentihash%253Ab73a1aae1e15b9a7e2cc0d486449e132671aebec) |
| Authentihash SHA256| [fabe94809d90ade89dad012b22243e3fb755a131800140f8f8b30c989c371301](https://www.virustotal.com/gui/search/authentihash%253Afabe94809d90ade89dad012b22243e3fb755a131800140f8f8b30c989c371301) |
| Company           | Windows (R) Win 7 DDK provider |
| Description       | Voicemod Virtual Audio Device (WDM) |
| Product           | Windows (R) Win 7 DDK driver |
| OriginalFilename  | vmdrv.sys |

#### Certificates

{{< details "Expand" >}}

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* portcls.sys

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* portcls.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* KeClearEvent
* KeSetEvent
* ExFreePool
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ExEventObjectType
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ExSystemTimeToLocalTime
* _purecall
* KeInitializeDpc
* KeFlushQueuedDpcs
* KeInitializeMutex
* KeReleaseMutex
* KeInitializeTimerEx
* KeCancelTimer
* KeSetTimerEx
* KeWaitForSingleObject
* KeInitializeSpinLock
* IoAllocateWorkItem
* IoFreeWorkItem
* IoQueueWorkItem
* RtlIsNtDdiVersionAvailable
* PcInitializeAdapterDriver
* PcDispatchIrp
* PcAddAdapterDevice
* PcRegisterAdapterPowerManagement
* PcNewServiceGroup
* PcRegisterSubdevice
* PcRegisterPhysicalConnection
* PcNewPort

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
      "Signature": "208cc159ed6f9c6b2dc14a3e751d454c41501cbd80ead9b0928b062a133f53169e56396a8a63b6782479f57db8b947a10a96c2f6cbbda2669f06e1acd279090efd3cdcac020c70af3f1bec787ed4eb4b056026d973619121edb06863e09712ab6fa012edd99fd2da273cb3e456f9d1d4810f71bd427ca689dccdd5bd95a2abf193117de8ac3129a85d6670419dfc75c9d5b31a392ad08505508bac91cac493cb71a59da4946f580cfa6e20c40831b5859d7e81f9d23dca5b18856c0a86ec22091ba574344f7f28bc954aab1db698b05d09a477767eefa78e5d84f61824cbd16da6c3a19cc2107580ff9d32fde6cf433a82f7ce8fe1722a9b62b75fed951a395c2f946d48b7015f332fbbdc2d73348904420a1c8b79f9a3fa17effaa11a10dfe0b2c195eb5c0c05973b353e18884ddb6cbf24898dc8bdd89f7b393a24a0d5dfd1f34a1a97f6a66f7a1fb090a9b3ac013991d361b764f13e573803afce7ad2b590f5aedc3999d5b63c97eda6cb16c77d6b2a4c9094e64c54fd1ecd20ecce689c8758e96160beeb0ec9d5197d9fe978bd0eac2175078fa96ee08c6a2a6b9ce3e765bcbc2d3c6ddc04dc67453632af0481bca8006e614c95c55cd48e8e9f2fc13274bdbd11650307cdefb75e0257da86d41a2834af8849b2cfa5dd82566f68aa14e25954feffeaeeefea9270226081e32523c09fcc0f49b235aa58c33ac3d9169410",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA",
      "ValidFrom": "2011-04-15 19:45:33",
      "ValidTo": "2021-04-15 19:55:33"
    },
    {
      "Signature": "3d61f91d3417ea68406f8f16faa42f704866212beb1e47ede42931cefc8e5a240a6320d9cdc2eb1911c5a72db5514cdfa4a40e554c2874d9da134ef850077c6859f540b5d89f3e2168a0ad1b26ffa730588d98ec52b386174b06e96f6254c86315cb6c982c1f6c3748ec1f28b779cfee301ab12ce5fc1b817b018637dd93ac6419957f3d3dd4e362b8f34b41664444e4743c12309e9c14996430719db60684117206890b140b5e87f708838b3b53b5395a1e1a562840c2939c64e2e5f50c40d148830fdeb425077e74fbabfde856bf8ccb0036fbec5d49e58056200cdb24eba2382fc9a1b60ba342759097634855dfd66520763cf7c04c2b85abebd5b5057052",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=ES, ??=Private Organization, serialNumber=B98657844, C=ES, L=Valencia, O=Voicemod Sociedad Limitada, CN=Voicemod Sociedad Limitada",
      "ValidFrom": "2019-12-13 00:00:00",
      "ValidTo": "2020-12-17 12:00:00"
    },
    {
      "Signature": "19334a0c813337dbad36c9e4c93abbb51b2e7aa2e2f44342179ebf4ea14de1b1dbe981dd9f01f2e488d5e9fe09fd21c1ec5d80d2f0d6c143c2fe772bdbf9d79133ce6cd5b2193be62ed6c9934f88408ecde1f57ef10fc6595672e8eb6a41bd1cd546d57c49ca663815c1bfe091707787dcc98d31c90c29a233ed8de287cd898d3f1bffd5e01a978b7cda6dfba8c6b23a666b7b01b3cdd8a634ec1201ab9558a5c45357a860e6e70212a0b92364a24dbb7c81256421becfee42184397bba53706af4dff26a54d614bec4641b865ceb8799e08960b818c8a3b8fc7998ca32a6e986d5e61c696b78ab9612d93b8eb0e0443d7f5fea6f062d4996aa5c1c1f0649480",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2)",
      "ValidFrom": "2012-04-18 12:00:00",
      "ValidTo": "2027-04-18 12:00:00"
    }
  ],
  "CertificatesInfo": [],
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2)",
      "SerialNumber": "02c5372170daa825b5e24b614268c5b5"
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | vmdrv.sys |
| MD5                | [0e625b7a7c3f75524e307b160f8db337](https://www.virustotal.com/gui/file/0e625b7a7c3f75524e307b160f8db337) |
| SHA1               | [5088c71a740ef7c4156dcaa31e543052fe226e1c](https://www.virustotal.com/gui/file/5088c71a740ef7c4156dcaa31e543052fe226e1c) |
| SHA256             | [d884ca8cc4ef1826ca3ab03eb3c2d8f356ba25f2d20db0a7d9fc251c565be7f3](https://www.virustotal.com/gui/file/d884ca8cc4ef1826ca3ab03eb3c2d8f356ba25f2d20db0a7d9fc251c565be7f3) |
| Authentihash MD5   | [b402effbea875040846c88d9b8b08b36](https://www.virustotal.com/gui/search/authentihash%253Ab402effbea875040846c88d9b8b08b36) |
| Authentihash SHA1  | [08e1ee43f0e00155730448f017a4616efa2afdf0](https://www.virustotal.com/gui/search/authentihash%253A08e1ee43f0e00155730448f017a4616efa2afdf0) |
| Authentihash SHA256| [57ae8d2d962cdde554831415725583fcf4ae5fc844c19983a7c37e31b12109a3](https://www.virustotal.com/gui/search/authentihash%253A57ae8d2d962cdde554831415725583fcf4ae5fc844c19983a7c37e31b12109a3) |
| Company           | Windows (R) Win 7 DDK provider |
| Description       | Voicemod Virtual Audio Device (WDM) |
| Product           | Windows (R) Win 7 DDK driver |
| OriginalFilename  | vmdrv.sys |

#### Certificates

{{< details "Expand" >}}

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* portcls.sys

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* portcls.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* RtlInitUnicodeString
* KeClearEvent
* KeSetEvent
* ExFreePool
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ExEventObjectType
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ExSystemTimeToLocalTime
* _purecall
* KeInitializeDpc
* KeFlushQueuedDpcs
* KeInitializeMutex
* KeReleaseMutex
* KeInitializeTimerEx
* KeCancelTimer
* KeSetTimerEx
* KeWaitForSingleObject
* KeInitializeSpinLock
* KeAcquireSpinLockRaiseToDpc
* KeReleaseSpinLock
* IoAllocateWorkItem
* IoFreeWorkItem
* IoQueueWorkItem
* RtlIsNtDdiVersionAvailable
* PcInitializeAdapterDriver
* PcDispatchIrp
* PcAddAdapterDevice
* PcRegisterAdapterPowerManagement
* PcNewServiceGroup
* PcRegisterSubdevice
* PcRegisterPhysicalConnection
* PcNewPort

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
      "Signature": "208cc159ed6f9c6b2dc14a3e751d454c41501cbd80ead9b0928b062a133f53169e56396a8a63b6782479f57db8b947a10a96c2f6cbbda2669f06e1acd279090efd3cdcac020c70af3f1bec787ed4eb4b056026d973619121edb06863e09712ab6fa012edd99fd2da273cb3e456f9d1d4810f71bd427ca689dccdd5bd95a2abf193117de8ac3129a85d6670419dfc75c9d5b31a392ad08505508bac91cac493cb71a59da4946f580cfa6e20c40831b5859d7e81f9d23dca5b18856c0a86ec22091ba574344f7f28bc954aab1db698b05d09a477767eefa78e5d84f61824cbd16da6c3a19cc2107580ff9d32fde6cf433a82f7ce8fe1722a9b62b75fed951a395c2f946d48b7015f332fbbdc2d73348904420a1c8b79f9a3fa17effaa11a10dfe0b2c195eb5c0c05973b353e18884ddb6cbf24898dc8bdd89f7b393a24a0d5dfd1f34a1a97f6a66f7a1fb090a9b3ac013991d361b764f13e573803afce7ad2b590f5aedc3999d5b63c97eda6cb16c77d6b2a4c9094e64c54fd1ecd20ecce689c8758e96160beeb0ec9d5197d9fe978bd0eac2175078fa96ee08c6a2a6b9ce3e765bcbc2d3c6ddc04dc67453632af0481bca8006e614c95c55cd48e8e9f2fc13274bdbd11650307cdefb75e0257da86d41a2834af8849b2cfa5dd82566f68aa14e25954feffeaeeefea9270226081e32523c09fcc0f49b235aa58c33ac3d9169410",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA",
      "ValidFrom": "2011-04-15 19:45:33",
      "ValidTo": "2021-04-15 19:55:33"
    },
    {
      "Signature": "3d61f91d3417ea68406f8f16faa42f704866212beb1e47ede42931cefc8e5a240a6320d9cdc2eb1911c5a72db5514cdfa4a40e554c2874d9da134ef850077c6859f540b5d89f3e2168a0ad1b26ffa730588d98ec52b386174b06e96f6254c86315cb6c982c1f6c3748ec1f28b779cfee301ab12ce5fc1b817b018637dd93ac6419957f3d3dd4e362b8f34b41664444e4743c12309e9c14996430719db60684117206890b140b5e87f708838b3b53b5395a1e1a562840c2939c64e2e5f50c40d148830fdeb425077e74fbabfde856bf8ccb0036fbec5d49e58056200cdb24eba2382fc9a1b60ba342759097634855dfd66520763cf7c04c2b85abebd5b5057052",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "??=ES, ??=Private Organization, serialNumber=B98657844, C=ES, L=Valencia, O=Voicemod Sociedad Limitada, CN=Voicemod Sociedad Limitada",
      "ValidFrom": "2019-12-13 00:00:00",
      "ValidTo": "2020-12-17 12:00:00"
    },
    {
      "Signature": "19334a0c813337dbad36c9e4c93abbb51b2e7aa2e2f44342179ebf4ea14de1b1dbe981dd9f01f2e488d5e9fe09fd21c1ec5d80d2f0d6c143c2fe772bdbf9d79133ce6cd5b2193be62ed6c9934f88408ecde1f57ef10fc6595672e8eb6a41bd1cd546d57c49ca663815c1bfe091707787dcc98d31c90c29a233ed8de287cd898d3f1bffd5e01a978b7cda6dfba8c6b23a666b7b01b3cdd8a634ec1201ab9558a5c45357a860e6e70212a0b92364a24dbb7c81256421becfee42184397bba53706af4dff26a54d614bec4641b865ceb8799e08960b818c8a3b8fc7998ca32a6e986d5e61c696b78ab9612d93b8eb0e0443d7f5fea6f062d4996aa5c1c1f0649480",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2)",
      "ValidFrom": "2012-04-18 12:00:00",
      "ValidTo": "2027-04-18 12:00:00"
    }
  ],
  "CertificatesInfo": [],
  "Signer": [
    {
      "Issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert EV Code Signing CA (SHA2)",
      "SerialNumber": "02c5372170daa825b5e24b614268c5b5"
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/2ea12acc-95b6-4f91-afb7-8ded7a2fe9d9.yaml)

*last_updated:* 2023-06-24








{{< /column >}}
{{< /block >}}
