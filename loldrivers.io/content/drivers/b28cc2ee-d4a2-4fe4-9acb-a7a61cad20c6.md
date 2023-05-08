+++

description = ""
title = "b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WiseUnlo.sys


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6 is a vulnerable driver and more information will be added as found.
- **UUID**: b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/356bda2bf0f6899a2c08b2da3ec69f13.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WiseUnlo.sys binPath=C:\windows\temp\WiseUnlo.sys type=kernel &amp;&amp; sc.exe start WiseUnlo.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | WiseUnlo.sys |
| MD5                | [356bda2bf0f6899a2c08b2da3ec69f13](https://www.virustotal.com/gui/file/356bda2bf0f6899a2c08b2da3ec69f13) |
| SHA1               | [b9807b8840327c6d7fbdde45fc27de921f1f1a82](https://www.virustotal.com/gui/file/b9807b8840327c6d7fbdde45fc27de921f1f1a82) |
| SHA256             | [358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69](https://www.virustotal.com/gui/file/358ac54be252673841a1d65bfc2fb6d549c1a4c877fa7f5e1bfa188f30375d69) |
| Authentihash MD5   | [6d1e6e5682f9a5e8a64dc8d2ec6ddfac](https://www.virustotal.com/gui/search/authentihash%253A6d1e6e5682f9a5e8a64dc8d2ec6ddfac) |
| Authentihash SHA1  | [49fb554b77c8d533e4a1ff30bbc60ef7f80b7055](https://www.virustotal.com/gui/search/authentihash%253A49fb554b77c8d533e4a1ff30bbc60ef7f80b7055) |
| Authentihash SHA256| [c36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7](https://www.virustotal.com/gui/search/authentihash%253Ac36ace67f4e25f391e8709776348397e4fd3930e641b32c1b0da398e59199ca7) |
| Company           | WiseCleaner.com |
| Description       | WiseUnlo |
| Product           | WiseUnlo |
| OriginalFilename  | WiseUnlo.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* IoGetRelatedDeviceObject
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* IoCreateFile
* KeInitializeEvent
* IoFileObjectType
* ZwClose
* IofCompleteRequest
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* IoFreeIrp
* IoAllocateIrp
* IoCreateSymbolicLink
* ObfDereferenceObject
* IoCreateDevice
* DbgPrint
* IofCallDriver

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
      "Signature": "664eecb716776f11e81b5d6a4ed9f28b6cb15628408bc031c49948233df80ee88097ef6d200b1f13c486fb173415e18e54f7c2b8007315e028d9dabafa8254c2f7ebbfc336d0309fe5a11c94dfef7ce8f62c78a2accf266a15a11531d6313498bd534fc48483a3c4965c3dd8fed6f954ff67936df83e2b6b2ca2087c5648813218b26eac90c1dbe4de398b86e5c7184059a4df9647bab27fb1f8570f858074380e3a58621efe52e3e6ae530986fe8f9bdb5656cc07b089c104f1530b6c6f77ecb21fecf65b4043600f1bab1854b410048ef80ee9cb83b17af2344e6a544ce9832ae9b030251cce628e0eeb85e629feb14ae3f2ae3c91f54ca1bec8170e5cbb424de31a8a92cd3e207edde975b1ea1f745c9e54c29437b261dd0716597f968016e099b5d26eb0c9230615acd123f4338bce75f0c186d3ffe12efa904ffe46f9bbdb4fbbb7fed10d2b04f1d2d195852c8a2eb88556f2c38452a1e933b1eb50c8a1b09fe3c38b3a879ee755d3d36d3417300d68220bd5b9ed733572c3eda737cde343ae45cd34bf28ca8762ed43a4affacb31cb215861465eb6c67aa61e532aa8f85c511f3a5a100f28c0e4748b74c604aaf84b26280a3289db9d2a60716ac3964e16b963bf6195678c4b2ebbb04e83e94d31e58e2722f53c267b4491d3d45af0d37cf438be149a990e8bb15beae48b0f119d7742821c5c3ad4daab882f8d573054",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.12",
      "Subject": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Extended Validation Code Signing CA",
      "ValidFrom": "2014-12-03 00:00:00",
      "ValidTo": "2029-12-02 23:59:59"
    },
    {
      "Signature": "81980792fe6f325fd9d24bf57dd971e0fdfc169205b4ce67f5cc4bd4c7109854fa521b48582f73bf19d937a0ad33f351052379d9b277648aebbdc3b39db7b1e637d1d2597e41d98fb314ab15774d6cda40245bb207b8582c4b0c2b5351b3df2eb976ac69c9c2ed64377b8d217accdc9fbc172804cc2547242a85cc56e639398775181f46f6910faa46fa4de64754e2322c76eefbcdbd62e1962429064b0cfe344ae9101d74e57a2f954bcc6ebafdd7355f91e45942defb008e08f151512d62258415081911864061d52553232c297738cc58d38c5fbc19b866064c6310dbb2ac306c16bc8bbcd21bc603131546a550f49a9684bb721038db519ad4c55327cbbf28159e086b3d3f4cc00c911cbf19848b3751a0199d8555c55da56479ef10a5ebf4231cda6fe32e7d17b037761f4d8dc102411f363e067bc5b7602d416251dedde4512da7de81f4c3e0e0e9c31680dd9c497d17cfcb556307d66952f4a49d248dbe1bc98099874548cb49c5ed703500267ca70f7532f7ed088ff0bca560a022d5331efbe5022c95a607f4be14de704c8ea97e41dea9d95064866f9424f7abf683955d0d45d18c238c030a13e40eb943030a4367b3107446e46dbd65de4541867072040bbaddba591f571393b00bedb1144169d3090459c7368e7db64b9df120fcd0f18bbd68ca3eb131cf43d066f5a3ddafb1dcc3178cfa3128c73e4927ab6a1b",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority",
      "ValidFrom": "2011-04-11 22:06:20",
      "ValidTo": "2021-04-11 22:16:20"
    },
    {
      "Signature": "0813de16aad5aae2206ec189ee90af05a8a8b9d096e6812c419f8a6320ea5936e3089eb2abf2022a5e946464d9a3cb09d0b041ce8dd90c37d791f5e3fdafa755ad2fd7fbd7da760fa4bbaeba655509ad015c5f37df20229360fb596ebb7a91b644f7a86ef28c4f8d16debe8666f4d6ebefd7d4a4d5d8c3b96d36c54ebc0386ae680dd469dc252893eca2fba6929f4e589974cf6cb1d33fa8270b67d606dc4118ee320a1cb2894a7ea655dbf42f9ef9c2e204a736a62e326ef85afad054c8f38506b050580120383f3136b33f8f6160bddabbe9cdc3c9d130d2915a5987951d7237bb2480172bb326256efa866a88f4e4432b844a69892ea38c560dde939f18d7",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
      "Subject": "serialNumber=91110101593898951F, ??=CN, ??=Private Organization, C=CN, postalCode=100028, ST=Beijing Shi, L=Beijing, ??=Chaoyang District, ??=Room 1610, Haocheng Building, No.9 Building, No.6 Courtyard, Zuojiazhuang Middle Street, O=Lespeed Technology Co., Ltd, CN=Lespeed Technology Co., Ltd",
      "ValidFrom": "2020-07-09 00:00:00",
      "ValidTo": "2023-07-09 23:59:59"
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Extended Validation Code Signing CA",
      "SerialNumber": "2e4a279bde2eb688e8ab30f5904fa875"
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6.yaml)

*last_updated:* 2023-05-08








{{< /column >}}
{{< /block >}}
