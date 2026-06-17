+++

description = ""
title = "dbd78de7-f5ab-4fb7-a246-39cbcca4678c"
weight = 10
displayTitle = "deresute64.sys"
+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# deresute64.sys ![:inline](/images/twitter_verified.png)  ![:inline](/images/elmo.gif) 

### Description

Create and start driver
- **UUID**: dbd78de7-f5ab-4fb7-a246-39cbcca4678c
- **Created**: 2026-05-05
- **Author**: Pierre-Henri Pezier
- **Acknowledgement**: Nextron Research | [@nextronresearch](https://twitter.com/@nextronresearch)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b7d34956622d0adc9242fb3f17944043.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

{{< blockbanner "deresute64.sys" >}}
### Commands

```
sc.exe create deresute64.sys binPath=C:\windows\temp\deresute64.sys type=kernel &amp;&amp; sc.exe start deresute64.sys
```


| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Load a kernel driver | kernel | Windows 10 |



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
<li><a href="https://x.com/nextronresearch/status/2051653303893680456">https://x.com/nextronresearch/status/2051653303893680456</a></li>
<br>


### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | andappsvc2_64.sys |
| Creation Timestamp           | 2023-11-06 17:32:55 |
| MD5                | [b7d34956622d0adc9242fb3f17944043](https://www.virustotal.com/gui/file/b7d34956622d0adc9242fb3f17944043) |
| SHA1               | [074de2138433c15f50c95dc1fec24d58f56644c2](https://www.virustotal.com/gui/file/074de2138433c15f50c95dc1fec24d58f56644c2) |
| SHA256             | [09a5ca7673f3734f8987b2b4d69255ffaa05cd2e77cf2d6f72a2d6a3c91139fb](https://www.virustotal.com/gui/file/09a5ca7673f3734f8987b2b4d69255ffaa05cd2e77cf2d6f72a2d6a3c91139fb) |
| Authentihash MD5   | [4fe744dd84e7e343417adf511f4e5ca0](https://www.virustotal.com/gui/search/authentihash%253A4fe744dd84e7e343417adf511f4e5ca0) |
| Authentihash SHA1  | [0fe1af745d86f9bbe889ee8ac4ef8639e9155afe](https://www.virustotal.com/gui/search/authentihash%253A0fe1af745d86f9bbe889ee8ac4ef8639e9155afe) |
| Authentihash SHA256| [9fee77b87c5726fe35fa349784f1304caa3a0b789a4c75ced2697df2269df19b](https://www.virustotal.com/gui/search/authentihash%253A9fee77b87c5726fe35fa349784f1304caa3a0b789a4c75ced2697df2269df19b) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 01:32 AM 11/07/2023 |
| OriginalFilename  | andappsvc2_64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b7d34956622d0adc9242fb3f17944043.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000062f45cf99e58a96a89000000000062
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 93c79f426eb2f2a03b74a6275cac238f  |
| ToBeSigned (TBS) SHA1             | e3ae60577ad97b4113d71845e11bd33a1ef2bea8 |
| ToBeSigned (TBS) SHA256           | 0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2023-04-06 19:16:30 |
| ValidTo                           | 2024-04-03 19:16:30 |
| Signature                         | 46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000062f45cf99e58a96a89000000000062 |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | usrdrv018064.sys |
| Creation Timestamp           | 2025-11-05 23:11:22 |
| MD5                | [9d9314faa1c0c4962c075c64698a262e](https://www.virustotal.com/gui/file/9d9314faa1c0c4962c075c64698a262e) |
| SHA1               | [a30cd72f9a1528001cda841531b016c752c72ce1](https://www.virustotal.com/gui/file/a30cd72f9a1528001cda841531b016c752c72ce1) |
| SHA256             | [1f280d67ff50607e1435b1c10f67c633d681801bcad0d8870128b3698c10634d](https://www.virustotal.com/gui/file/1f280d67ff50607e1435b1c10f67c633d681801bcad0d8870128b3698c10634d) |
| Authentihash MD5   | [a3b23ebf3308772db4283ebd5102d9ce](https://www.virustotal.com/gui/search/authentihash%253Aa3b23ebf3308772db4283ebd5102d9ce) |
| Authentihash SHA1  | [7cdcb102edc0dc4382fda104e5c2df2a67f06620](https://www.virustotal.com/gui/search/authentihash%253A7cdcb102edc0dc4382fda104e5c2df2a67f06620) |
| Authentihash SHA256| [5b0fc1bff6d7cb5ddbaafd13a886cebeda5627d12ce498cbb2a76e892cb41c43](https://www.virustotal.com/gui/search/authentihash%253A5b0fc1bff6d7cb5ddbaafd13a886cebeda5627d12ce498cbb2a76e892cb41c43) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 07:11 AM 11/06/2025 |
| OriginalFilename  | usrdrv018064.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9d9314faa1c0c4962c075c64698a262e.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000074ff3d4a9e7c401e86000000000074
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 846e2b51dbe3b3cdd48503e99cbce6a6  |
| ToBeSigned (TBS) SHA1             | 77940716d023ecae58709321c2b6a30df8e3d86d |
| ToBeSigned (TBS) SHA256           | 1dc33c8d9456aa23f43eb0c09beeb7b3565770f7e05d12d7b88575a4c61fa31f |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2025-07-16 20:48:20 |
| ValidTo                           | 2026-07-14 20:48:20 |
| Signature                         | b9ad07972990d4f7f1d20dddce037fbf8c19c8fc17ec991a97b0f3d3ac6b792c100f660abcf1eea23ce0eafaae637cb21524c9eb170657b4e3b45bc07fcbe811227491344f510071ddf12fa883ac943d0c0ec3d7c91468dc65b4373d62b939e66fe0f26098912ed0add0c44ff71b32e58db5bc56235c16b533e0ab06e9794e41a38bab04dfa510dddad2291a5c74c28ae750c0937ebaa640452d4708109d08a4e8b9e80a670f54ab2e575158b4e3f491c8a483fe36abb5f5f604a38578fd9a77f817824b1979c1f7b3a5fcd3e14ec6901e9ecc60e58bc4ab39d8ba6aa819d04ec3871d211963d2d34785d75ea15648052847a8572c7d89db4253fa67838639b395263564a561d02e60a7cdc52e65f725166deed0c847c1105350918bd149e889f1dbe604f74aa0110ca1598906e3f1c5efaeda772e51d5f89992258f893aba1baa1c8a14dd59d8f57aa742ee2251b99ce6655f0bcd920760c5a452a5fe5e2f30652b5022d124348161ce86060652b6b84abc60043da659d3e91bb7ce18adbbbb94fa19130947a4a651af21a33d58cafcd5d920016858ddf2b5df3e7dc3bc8a1b66edf03cbca7c40048dae606f66e55692edcd698773d391be409c2895f71fddb7494d28fa3bd30aae628d7967204708b509e551c86cd3a1cbef68796c15e71e15e5dcfc5914352f9991fcd57c5112e03d8c2441cb643bc6bbdfb261bda63746f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000074ff3d4a9e7c401e86000000000074 |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | Umamusume64_2.sys |
| Creation Timestamp           | 2023-12-14 18:08:08 |
| MD5                | [165900b09295d79bf0b53f3acd2a9aa3](https://www.virustotal.com/gui/file/165900b09295d79bf0b53f3acd2a9aa3) |
| SHA1               | [3406929eb81855c878261c897f9b452aed3aa3ea](https://www.virustotal.com/gui/file/3406929eb81855c878261c897f9b452aed3aa3ea) |
| SHA256             | [079842b1c4fae65b5c6af3e75a7305a263865cd033696a5a2fe7ea707e0c3d71](https://www.virustotal.com/gui/file/079842b1c4fae65b5c6af3e75a7305a263865cd033696a5a2fe7ea707e0c3d71) |
| Authentihash MD5   | [16777e3d2942a22ea0e853cead1af8eb](https://www.virustotal.com/gui/search/authentihash%253A16777e3d2942a22ea0e853cead1af8eb) |
| Authentihash SHA1  | [f4d9ea94b248e4091b8dc712dfa27dcbe0e71acb](https://www.virustotal.com/gui/search/authentihash%253Af4d9ea94b248e4091b8dc712dfa27dcbe0e71acb) |
| Authentihash SHA256| [3257940a4fee01241e1475daa884934aaf9ee9d47b9d6e83fc68a36f736c8dd3](https://www.virustotal.com/gui/search/authentihash%253A3257940a4fee01241e1475daa884934aaf9ee9d47b9d6e83fc68a36f736c8dd3) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 02:08 AM 12/15/2023 |
| OriginalFilename  | Umamusume64_2.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/165900b09295d79bf0b53f3acd2a9aa3.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000062f45cf99e58a96a89000000000062
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 93c79f426eb2f2a03b74a6275cac238f  |
| ToBeSigned (TBS) SHA1             | e3ae60577ad97b4113d71845e11bd33a1ef2bea8 |
| ToBeSigned (TBS) SHA256           | 0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2023-04-06 19:16:30 |
| ValidTo                           | 2024-04-03 19:16:30 |
| Signature                         | 46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000062f45cf99e58a96a89000000000062 |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | usrdrv118064.sys |
| Creation Timestamp           | 2024-03-13 19:12:27 |
| MD5                | [05c0f275cb3270e196d099e13e23612d](https://www.virustotal.com/gui/file/05c0f275cb3270e196d099e13e23612d) |
| SHA1               | [62d68301154018e04f456a000a24fe9f5048ec52](https://www.virustotal.com/gui/file/62d68301154018e04f456a000a24fe9f5048ec52) |
| SHA256             | [79c2d06072e004639ea3b27c405d5cbb50a0af3531b743521c2b4a42557cc26f](https://www.virustotal.com/gui/file/79c2d06072e004639ea3b27c405d5cbb50a0af3531b743521c2b4a42557cc26f) |
| Authentihash MD5   | [ed4bcd3278a71332a62268b54bca47bc](https://www.virustotal.com/gui/search/authentihash%253Aed4bcd3278a71332a62268b54bca47bc) |
| Authentihash SHA1  | [3e07ff7a833ba957822e13a2f25e7e4a0e368025](https://www.virustotal.com/gui/search/authentihash%253A3e07ff7a833ba957822e13a2f25e7e4a0e368025) |
| Authentihash SHA256| [0dcdeb561d4cbe26be3a68ca205f6f0dfb0de6df1757c996474bc6dde526dc0c](https://www.virustotal.com/gui/search/authentihash%253A0dcdeb561d4cbe26be3a68ca205f6f0dfb0de6df1757c996474bc6dde526dc0c) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 02:12 AM 03/14/2024 |
| OriginalFilename  | usrdrv118064.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/05c0f275cb3270e196d099e13e23612d.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 33000000699d42c97675b50882000000000069
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 49cb41d3f01f459bbbacb65cb9dffb2f  |
| ToBeSigned (TBS) SHA1             | ace514a82530e92c1d7916d1a3b58be972aa660c |
| ToBeSigned (TBS) SHA256           | ea9539b995f79e1ef05650e777887c484c057b25d510a159f1a7856ce0e742de |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2024-01-11 20:09:15 |
| ValidTo                           | 2025-01-10 20:09:15 |
| Signature                         | 228d55d2a15bd3ce2c6a38898b66d52bf71d58ba49cd5818493fc17600146ed7f8944701bb39ea4127e9687175f35d9e89973d457d1d61fed4c960c9870dfd1bfe3fb78a4160a05436cf50e616693b89e5425b7a5a7f59c6ae804531b2a00b02c675fe834b1c429441b881518c625c1d55ff07a70ff8507e6eb53b43a3b738341b952594daee42c54ffb55126a04611b70601b02ed4405bedd33fa0bc60b23363b399d4fa0f146a17a1b08b0a26d222a5b76c79f78333db88d91f51e1b42ff3d0c1025603d50ea72535c1afa866a73a05def702f7526ece3efe3a926d72d4c1dc6a4f129711e29fb8255b2c4b21b1fbb497d071404c2fa9198d58305f7c499e69bd5ae2cbcad016376f5f991bf5873b9a7f8d9c5f89456e7da56260823c4ac599b64a8cb04047634246875c11f2e1f5eaa3cd76ae55191a73ee7bf84f0e11416532549ff72d4923f914c2695bbf58b0a6fed9e2580f5a79fa3616f753d91328f9ce45cbed45cba84df4d3e7cde354d58540f983bee532ea141c66c974d00bd848ba67503ea492e16914bab4f957004f5715f6d36840d9bf9dfa13677b7b8eaf086cb04bbe47347f1ef4f678a56b146f4ec82a8eeeb7a8dab9d6556bd180990971093df61f8fc1bfde24b9ad0c6f919476bf780664778ae99770dc6109771979d6a50b1cf84748714d011f37ccd946fb83b3dccd655e347365988ce24578d4173 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 33000000699d42c97675b50882000000000069 |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | usrdrv017864.sys |
| Creation Timestamp           | 2025-04-01 19:58:29 |
| MD5                | [5480873d19c83b3cb8d5542f03c4182d](https://www.virustotal.com/gui/file/5480873d19c83b3cb8d5542f03c4182d) |
| SHA1               | [cfed486846db08c66afccfcfcba9d458162eed15](https://www.virustotal.com/gui/file/cfed486846db08c66afccfcfcba9d458162eed15) |
| SHA256             | [65b2956b1f1f26136b692d91de8ad98d6590b7f5b94d0acc88bbc61f8228a579](https://www.virustotal.com/gui/file/65b2956b1f1f26136b692d91de8ad98d6590b7f5b94d0acc88bbc61f8228a579) |
| Authentihash MD5   | [26d16cf0147cbe1c9e4d3b4863926501](https://www.virustotal.com/gui/search/authentihash%253A26d16cf0147cbe1c9e4d3b4863926501) |
| Authentihash SHA1  | [54f2d2cc9be0bc0dfc46e23ef8742f13a8c90a5c](https://www.virustotal.com/gui/search/authentihash%253A54f2d2cc9be0bc0dfc46e23ef8742f13a8c90a5c) |
| Authentihash SHA256| [e3f30a5653a65584894a1688c0ec9e1f49b184684c53b6082495f2b945f95371](https://www.virustotal.com/gui/search/authentihash%253Ae3f30a5653a65584894a1688c0ec9e1f49b184684c53b6082495f2b945f95371) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 03:58 AM 04/02/2025 |
| OriginalFilename  | usrdrv017864.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/5480873d19c83b3cb8d5542f03c4182d.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 330000006daa072f958218c9e300000000006d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4320213204f73b9d506bbcbb35111c2d  |
| ToBeSigned (TBS) SHA1             | d3cbbc8331d4d84555a6726d48dfd9571738bd25 |
| ToBeSigned (TBS) SHA256           | fe99f47e601d6b8ab1e89961000f680bf3b0e0629a8a59864e76f135e0c89699 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2024-10-10 19:04:52 |
| ValidTo                           | 2025-10-08 19:04:52 |
| Signature                         | 1bfc71b1c6ae1f779c132566b0692231de393c7578f2ae3adafa2968f4c01599d9dde8827a1f2ec65c46c56cad36987c0df5b1ec1c36576126f5fb988923b3c7f3f111749105254facfc1831516dba7fa7265753447f94b11979a3e9aba7f5dbd87e3f0f034229a34c7fb10cb7a90f197ffd35432e4244ee7666d4a48de1586b61b1072d441cd345eb140b613fd0fef87ab5eef73985d940029d30870053909e8550e94cb4e63696e82a182a7632267efb6056cf7c7b05c108645ea8698bba379bfa31e6bf7e179edbc3e559bbfe1fa8bf5c6b0c783edebac68aefa287bd16c1fcf2e00839c693e40e79f7c63447712a321c2ca5ee1dd2a0e03bde2702d9320a50d20439f395257fb6c5af0c11432c52801127d4bc45c0a65c660f5769fdf250aaba99a74bef0885f21a040f11e6364ba7499c795b39ca0972ff857d4e7c9bc08f257cb8dadb28817b62de202f3639de9db076ad8ee6b71a3cea1a1a476a510a3197fce4592654389629c6108656d9132971b2e55f3d19963d966a6869712265b662dcc7c92d6e3659d429c814f3efdf05ded84fe8654a039222dbe133a7992e04f05d8d7642ceb159cc705b832ec2f507ba8604047a01ff37fd69397ad861ad766df8e4e296199d81d89f708550a04d774da5c1b50062e06a72badcdb12f94820b5b834442ada4a82ce25d0450a519cac28d8362bd182257b1b80cf930e92d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 330000006daa072f958218c9e300000000006d |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | deresute64.sys |
| Creation Timestamp           | 2023-11-20 18:08:14 |
| MD5                | [b78864853fc27438b3df480bf3ceddc7](https://www.virustotal.com/gui/file/b78864853fc27438b3df480bf3ceddc7) |
| SHA1               | [b040522bf83a7aab46b1bab007d8c122cc446967](https://www.virustotal.com/gui/file/b040522bf83a7aab46b1bab007d8c122cc446967) |
| SHA256             | [52591fc20b01ab714543e97b4fcbcfad630d50a4725d98da6f11e9bd5b1cf5bb](https://www.virustotal.com/gui/file/52591fc20b01ab714543e97b4fcbcfad630d50a4725d98da6f11e9bd5b1cf5bb) |
| Authentihash MD5   | [67188ad94eba50e19930744bbe56bffe](https://www.virustotal.com/gui/search/authentihash%253A67188ad94eba50e19930744bbe56bffe) |
| Authentihash SHA1  | [298e46103d0d622edca4773d27181056c88f3111](https://www.virustotal.com/gui/search/authentihash%253A298e46103d0d622edca4773d27181056c88f3111) |
| Authentihash SHA256| [721ab86e40648e8e23db4b87f0a74de4b422262fba2dbafb533eb6ae2feaf067](https://www.virustotal.com/gui/search/authentihash%253A721ab86e40648e8e23db4b87f0a74de4b422262fba2dbafb533eb6ae2feaf067) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 02:08 AM 11/21/2023 |
| OriginalFilename  | deresute64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b78864853fc27438b3df480bf3ceddc7.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000061c88b129c2a7f1d87000000000061
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 686c5dd3e6c0c4d6888c652ee9a76e0b  |
| ToBeSigned (TBS) SHA1             | 48c84f19d968d167bb3dad0bfeffcc659269aa03 |
| ToBeSigned (TBS) SHA256           | 1fe207964146bdf934dc0c17aefaa75e78aea3d6a3935cc96e64511d7d469b29 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2023-04-06 19:16:28 |
| ValidTo                           | 2024-04-03 19:16:28 |
| Signature                         | 0449290d26112d6053cc65c76ab953df62d870517fec16470e3bef28a20b21c099f4609adc713af367ac47fe49cb0f22c001e774ca0c9b13e86c59ec4b03ccdff30a8d38960e09584a895e6a87b0a481a57dc0ef10819ce8b226667f6a646adff7bfa61981a31ed6890e65afa47e7f27991e13fe39a54544aff9116bf5a737a4c33c92c1659a58b33cf3aa94b997e0c636f30e90776eb343874c6e0c7efa3a2d135ec3dd781b97e6ad41fc21adc7bd9b2d9b49e504a32846f541349c64f41396b43622015916fe46907431768a58c24e3f8d46c5cd8276fa1d92ba7aab4ccd77c5f7778b3fa0f5afa6fe6bfdba544b5af0a8597a073b0c7eed8caa5a11cb9dc4c415c8119bd2545f77b93886c40842a9b28b3128bcd257a4365c1e7afa22a5a2d46b936ed7ff7fa1db7801f26552c3ebd7832cc9475390ecbf3898855d16f270652b7fcc319d2415e2b10e8f61f0f4b6c7187739ed7752978fe4870650f3cd838f19b9c43804324f093eba2591c09cdcd46f1f0f8ad10779eed7467030721563f4e810982b42f8c6dfcfd0401d4569a74ccc13df5a9d2347883e776e98ed7fb32bb3f99c688e30b92c78c756b5242c632e5692a5bf564060961f5d55cfb82f150a50714885b378ce803b505b52c99ee339d84f6b9a5e6b86819c525088d9785771e3d1ed24746abd12bd6348a11e5a1cb545228aa270d3ac67b9dcd93d19fdf4 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000061c88b129c2a7f1d87000000000061 |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | usrdrv017764.sys |
| Creation Timestamp           | 2025-01-19 17:02:56 |
| MD5                | [ed96f1a99a3693d40cc302d5ae0840b8](https://www.virustotal.com/gui/file/ed96f1a99a3693d40cc302d5ae0840b8) |
| SHA1               | [0707e4b64fd745d2887c3066fdda1eeda20e434b](https://www.virustotal.com/gui/file/0707e4b64fd745d2887c3066fdda1eeda20e434b) |
| SHA256             | [64035e86735d0c01e0eb0862def6a48f012ec0a8e701874092ee1506ab65d273](https://www.virustotal.com/gui/file/64035e86735d0c01e0eb0862def6a48f012ec0a8e701874092ee1506ab65d273) |
| Authentihash MD5   | [2808446ab3b0b417ba0a451bf23872c2](https://www.virustotal.com/gui/search/authentihash%253A2808446ab3b0b417ba0a451bf23872c2) |
| Authentihash SHA1  | [dd79bb7dbb7679d3bf886467f90201d520436883](https://www.virustotal.com/gui/search/authentihash%253Add79bb7dbb7679d3bf886467f90201d520436883) |
| Authentihash SHA256| [c31a1e223df7ea4b48df23b4ab92110a5d8732e2383c326dbe521d84dbabf875](https://www.virustotal.com/gui/search/authentihash%253Ac31a1e223df7ea4b48df23b4ab92110a5d8732e2383c326dbe521d84dbabf875) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 01:02 AM 01/20/2025 |
| OriginalFilename  | usrdrv017764.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ed96f1a99a3693d40cc302d5ae0840b8.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 330000006daa072f958218c9e300000000006d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 4320213204f73b9d506bbcbb35111c2d  |
| ToBeSigned (TBS) SHA1             | d3cbbc8331d4d84555a6726d48dfd9571738bd25 |
| ToBeSigned (TBS) SHA256           | fe99f47e601d6b8ab1e89961000f680bf3b0e0629a8a59864e76f135e0c89699 |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2024-10-10 19:04:52 |
| ValidTo                           | 2025-10-08 19:04:52 |
| Signature                         | 1bfc71b1c6ae1f779c132566b0692231de393c7578f2ae3adafa2968f4c01599d9dde8827a1f2ec65c46c56cad36987c0df5b1ec1c36576126f5fb988923b3c7f3f111749105254facfc1831516dba7fa7265753447f94b11979a3e9aba7f5dbd87e3f0f034229a34c7fb10cb7a90f197ffd35432e4244ee7666d4a48de1586b61b1072d441cd345eb140b613fd0fef87ab5eef73985d940029d30870053909e8550e94cb4e63696e82a182a7632267efb6056cf7c7b05c108645ea8698bba379bfa31e6bf7e179edbc3e559bbfe1fa8bf5c6b0c783edebac68aefa287bd16c1fcf2e00839c693e40e79f7c63447712a321c2ca5ee1dd2a0e03bde2702d9320a50d20439f395257fb6c5af0c11432c52801127d4bc45c0a65c660f5769fdf250aaba99a74bef0885f21a040f11e6364ba7499c795b39ca0972ff857d4e7c9bc08f257cb8dadb28817b62de202f3639de9db076ad8ee6b71a3cea1a1a476a510a3197fce4592654389629c6108656d9132971b2e55f3d19963d966a6869712265b662dcc7c92d6e3659d429c814f3efdf05ded84fe8654a039222dbe133a7992e04f05d8d7642ceb159cc705b832ec2f507ba8604047a01ff37fd69397ad861ad766df8e4e296199d81d89f708550a04d774da5c1b50062e06a72badcdb12f94820b5b834442ada4a82ce25d0450a519cac28d8362bd182257b1b80cf930e92d0 |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 330000006daa072f958218c9e300000000006d |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
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
| Filename           | wfs64.sys |
| Creation Timestamp           | 2023-11-06 17:32:40 |
| MD5                | [73236c534a805826368406f849ca4e23](https://www.virustotal.com/gui/file/73236c534a805826368406f849ca4e23) |
| SHA1               | [371b65249aed01a48bdfb266083016a219108b91](https://www.virustotal.com/gui/file/371b65249aed01a48bdfb266083016a219108b91) |
| SHA256             | [740025dd6d222bc08b925692a6ef3bd5af86ecd030a8e8cef68b09f5da761fb2](https://www.virustotal.com/gui/file/740025dd6d222bc08b925692a6ef3bd5af86ecd030a8e8cef68b09f5da761fb2) |
| Authentihash MD5   | [d3b9c278912b765f93a03e1e5b9a81ce](https://www.virustotal.com/gui/search/authentihash%253Ad3b9c278912b765f93a03e1e5b9a81ce) |
| Authentihash SHA1  | [329fd5bbc921699d5583da5234f693a4e25fa829](https://www.virustotal.com/gui/search/authentihash%253A329fd5bbc921699d5583da5234f693a4e25fa829) |
| Authentihash SHA256| [44d64f2cbbb480f7a989f15ebb33fba6f0fae3b38e0c2c6c585c27f43ab0edc7](https://www.virustotal.com/gui/search/authentihash%253A44d64f2cbbb480f7a989f15ebb33fba6f0fae3b38e0c2c6c585c27f43ab0edc7) |
| RichPEHeaderHash MD5   | [89c0cb76b50a4d9e4c90a15f498e4fae](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A89c0cb76b50a4d9e4c90a15f498e4fae) |
| RichPEHeaderHash SHA1  | [3e177a1286ab6ebe7b3d1243c5103ca9cc568497](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A3e177a1286ab6ebe7b3d1243c5103ca9cc568497) |
| RichPEHeaderHash SHA256| [8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7](https://www.virustotal.com/gui/search/rich_pe_header_hash%253A8816e9fa07091c47e10541c9d76fd1f40bf41489acdb0732d41d7096e15ff2c7) |
| Publisher         | 株式会社ＤＮＰハイパーテック |
| Date                | 01:32 AM 11/07/2023 |
| OriginalFilename  | wfs64.sys |

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/73236c534a805826368406f849ca4e23.bin" "Download" >}} 

#### Certificates

{{< details "Expand" >}}
###### Certificate 3300000062f45cf99e58a96a89000000000062
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 93c79f426eb2f2a03b74a6275cac238f  |
| ToBeSigned (TBS) SHA1             | e3ae60577ad97b4113d71845e11bd33a1ef2bea8 |
| ToBeSigned (TBS) SHA256           | 0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher |
| ValidFrom                         | 2023-04-06 19:16:30 |
| ValidTo                           | 2024-04-03 19:16:30 |
| Signature                         | 46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | False |
| SerialNumber                      | 3300000062f45cf99e58a96a89000000000062 |
| Version                           | 3 |
###### Certificate 330000000d690d5d7893d076df00000000000d
| Field                             | Value                      |
|-----------------------------------|----------------------------|
| ToBeSigned (TBS) MD5              | 83f69422963f11c3c340b81712eef319  |
| ToBeSigned (TBS) SHA1             | 0c5e5f24590b53bc291e28583acb78e5adc95601 |
| ToBeSigned (TBS) SHA256           | d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae |
| Subject                           | C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014 |
| ValidFrom                         | 2014-10-15 20:31:27 |
| ValidTo                           | 2029-10-15 20:41:27 |
| Signature                         | 96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f |
| SignatureAlgorithmOID             | 1.2.840.113549.1.1.11 |
| IsCertificateAuthority            | True |
| SerialNumber                      | 330000000d690d5d7893d076df00000000000d |
| Version                           | 3 |

{{< /details >}}
#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### Imported Functions
{{< details "Expand" >}}
* PsGetCurrentProcessId
* PsGetProcessId
* PsGetProcessImageFileName
* PsGetProcessInheritedFromUniqueProcessId
* ZwQueryInformationProcess
* PsProcessType
* wcscat_s
* wcscpy_s
* ObUnRegisterCallbacks
* KeInitializeGuardedMutex
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetDeviceObjectPointer
* ObRegisterCallbacks
* RtlCopyUnicodeString
* IoGetCurrentProcess
* KeReleaseGuardedMutex
* RtlInitUnicodeString
* KeAcquireGuardedMutex
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
* .info
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
      "CertificateType": "Leaf (Code Signing)",
      "IsCA": false,
      "IsCertificateAuthority": false,
      "IsCodeSigning": true,
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Signature": "46265205ad9b6e72f93c97f9bf34c09a4a9f618fec8b7dd6ec24db2163c8b019835dab33b75917d152e60a82e374a0c824aabd01367487ae41dd80c6e98facf7ab35fb0e21b812444a0740d44e44c100b6edc2d3a5a243594b116a979fae9c2e5a0e8d8b9d3809064110d2427a911e520310562b1a3524d5b3767a94069e35c0a3df4f4e1d11f91c05e35bdcce15a12d0d0083f080b21de4d12c3cd428214ed47c21b2ecf546c3d258c90fc982530b04eb7b84fcad5c7898fb6ce95f8970d0d98ab02d730c33c75ced79ea3b9aa19938e719ad84889325a5de27e97c7715d7130926057292a83f09c89f0b5e3993f32de9f773016ba173520ae0d0559bfb4f78dc8564a66b619af0162abe1b02a812562d5517d681a5f096f73a8414bc414919c173240a48d5dd226caf91c1a7fc25b88d4d407af788d09452b324bdfecb7fbec11569e50dc596319701cdf5bd4e0d3714097054b84be6a9715cbf4d499a25a01114f02aa44973515379ebfa23bf8bbaf931f08fd998c4d63cbe8ca6b062145ba4379ad1fcd5749e226e14596ad99249c8c8009212f4a997cf6e4f4940c14a0d4733bc511189110958a9defce1668953a0ef3f17bd5d588af12fae2de418169c1ad1b3571584fcd7be4875ce8d4c10edfa60652327e39158c64eba0e1db8e85c8d07371603d60d2585a61f39f265d662240813567907809db37b3a38c50c1dab",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher",
      "TBS": {
        "MD5": "93c79f426eb2f2a03b74a6275cac238f",
        "SHA1": "e3ae60577ad97b4113d71845e11bd33a1ef2bea8",
        "SHA256": "0f06228de7bacfbf65d426df80c4e40c5abfe5a2a402e6221dea03b18897de2b",
        "SHA384": "4fcbd8696874577fdeed02d6f1245fb7f45d477850cbfdac0db27f478ed500665247ca122157f2678949f85e5386aa71"
      },
      "ValidFrom": "2023-04-06 19:16:30",
      "ValidTo": "2024-04-03 19:16:30",
      "Version": 3
    },
    {
      "CertificateType": "CA",
      "IsCA": true,
      "IsCertificateAuthority": true,
      "IsCodeSigning": false,
      "SerialNumber": "330000000d690d5d7893d076df00000000000d",
      "Signature": "96b5c33b31f27b6ba11f59dd742c3764b1bca093f9f33347e9f95df21d89f4579ee33f10a3595018053b142941b6a70e5b81a2ccbd8442c1c4bed184c2c4bd0c8c47bcbd8886fb5a0896ae2c2fdfbf9366a32b20ca848a6945273f732332936a23e9fffdd918edceffbd6b41738d579cf8b46d499805e6a335a9f07e6e86c06ba8086725afc0998cdba7064d4093188ba959e69914b912178144ac57c3ae8eae947bcb3b8edd7ab4715bba2bc3c7d085234b371277a54a2f7f1ab763b94459ed9230cce47c099212111f52f51e0291a4d7d7e58f8047ff189b7fd19c0671dcf376197790d52a0fbc6c12c4c50c2066f50e2f5093d8cafb7fe556ed09d8a753b1c72a6978dcf05fe74b20b6af63b5e1b15c804e9c7aa91d4df72846782106954d32dd6042e4b61ac4f24636de357302c1b5e55fb92b59457a9243d7c4e963dd368f76c728caa8441be8321a66cde5485c4a0a602b469206609698dcd933d721777f886dac4772daa2466eab64682bd24e98fb35cc7fec3f136d11e5db77edc1c37e1f6a4a14f8b4a721c671866770cdd819a35d1fa09b9a7cc55d4d728e74077fa74d00fcdd682412772a557527cda92c1d8e7c19ee692c9f7425338208db38cc7cc74f6c3a6bc237117872fe55596460333e2edfc42de72cd7fb0a82256fb8d70c84a5e1c4746e2a95329ea0fecdb4188fd33bad32b2b19ab86d0543fbff0d0f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "TBS": {
        "MD5": "83f69422963f11c3c340b81712eef319",
        "SHA1": "0c5e5f24590b53bc291e28583acb78e5adc95601",
        "SHA256": "d8be9e4d9074088ef818bc6f6fb64955e90378b2754155126feebbbd969cf0ae",
        "SHA384": "260ad59ba706420f68ba212931153bd89f760c464b21be55fba9d014fff322407859d4ebfb78ea9a3330f60dc9821a63"
      },
      "ValidFrom": "2014-10-15 20:31:27",
      "ValidTo": "2029-10-15 20:41:27",
      "Version": 3
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2014",
      "SerialNumber": "3300000062f45cf99e58a96a89000000000062",
      "Version": 1
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/dbd78de7-f5ab-4fb7-a246-39cbcca4678c.yaml)

*last_updated:* 2026-06-17

{{< /column >}}
{{< /block >}}
