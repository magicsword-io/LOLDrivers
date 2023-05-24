+++

description = ""
title = "f0fd5bc6-9ebd-4eb0-93ce-9256a5b9abf9"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinRing0x64.sys ![:inline](/images/twitter_verified.png) 


### Description

WinRing0x64.sys is a vulnerable driver and more information will be added as found.
- **UUID**: f0fd5bc6-9ebd-4eb0-93ce-9256a5b9abf9
- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0c0195c48b6b8582fa6f6373032118da.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create WinRing0x64.sys binPath=C:\windows\temp\WinRing0x64.sys     type=kernel &amp;&amp; sc.exe start WinRing0x64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |


### Detections
{{< button "https://github.com/magicsword-io/LOLDrivers/blob/yara_detections/detections/yara/11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5.yara" "YARA" "btn-danger" >}}
### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | WinRing0x64.sys |
| MD5                | [0c0195c48b6b8582fa6f6373032118da](https://www.virustotal.com/gui/file/0c0195c48b6b8582fa6f6373032118da) |
| SHA1               | [d25340ae8e92a6d29f599fef426a2bc1b5217299](https://www.virustotal.com/gui/file/d25340ae8e92a6d29f599fef426a2bc1b5217299) |
| SHA256             | [11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5](https://www.virustotal.com/gui/file/11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5) |
| Authentihash MD5   | [2bab314d894a026ac6073efe43c14a3d](https://www.virustotal.com/gui/search/authentihash%253A2bab314d894a026ac6073efe43c14a3d) |
| Authentihash SHA1  | [266821a39174d29f6f8791cf9f44f1a1f3439dda](https://www.virustotal.com/gui/search/authentihash%253A266821a39174d29f6f8791cf9f44f1a1f3439dda) |
| Authentihash SHA256| [1b845e5e43ce9e9b645ac198549e81f45c08197aad69708d96cdb9a719eb0e29](https://www.virustotal.com/gui/search/authentihash%253A1b845e5e43ce9e9b645ac198549e81f45c08197aad69708d96cdb9a719eb0e29) |
| Company           | OpenLibSys.org |
| Description       | WinRing0 |
| Product           | WinRing0 |
| OriginalFilename  | WinRing0.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IoDeleteDevice
* IoCreateDevice
* MmMapIoSpace
* KeBugCheckEx
* IoCreateSymbolicLink
* MmUnmapIoSpace
* IofCompleteRequest
* __C_specific_handler
* HalSetBusDataByOffset
* HalGetBusDataByOffset

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
      "Signature": "4b6c4ea808b550cbae0f97c27726a0445d0e3e021ee0e0087bfe5bbc290e3e45ca35333f2a97fb7667f64326629f7a99fe2fec4da9fe14f0d858419982b983457848fbd6a9115769db6c5626b4d2f87fc77019a755a9efdf81b1968dfbfa638bf87bd25a8adf1c6c3bba3735f06b54d127462ed40dc364ad4c4f29c9f9692b29ff9557300a7c0d395f250172e312ff253b7ce8885ef8c1fe60c448676180e4ca09b34b52ae116b01f22b446b827a748ca80aee5f8e9ff6725e1dce5a7984c26eb72a615a9ef272f6f7b2e03e6d34665caf506b93cb5a2de127177eb1923cf5bc499e312d6c43ff5a26124ea63a4dc9a3340daa6449c2322857adf98166423cfb",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=JP, CN=Noriyuki MIYAZAKI, emailAddress=hiyohiyo@crystalmark.info",
      "ValidFrom": "2007-09-24 10:50:55",
      "ValidTo": "2008-09-24 10:50:55"
    },
    {
      "Signature": "5c2f2e674a26b3e7b53f353cdda003ed569af9443752163065c7d14ea20f8db7b6b6678ee74cec8d95bee6cea7227874acd7f87499b3f7ce8b1338d596cc8d76c52f38b23aae61be0b8799e321626423398d84f6858df777ffb03806f07ec1485fb5ee582606660522749283a7dbb5f992e3e8c3192c2e63efbb1fdff9f70747660d0789977ef8332c9ecbae143df11cdfa3f179afc8928f9471c4d144c554db1eb50b0aa942a3afd643391dee8f9398585bbe6e9c0bf563ec5e99c2f954fa010746da0db06424cf8ed1061d4f3ca26377455ba4bc5fb080bb31e00b54015c161d724ed52a6947d11b667e5f016ef135916be02efeb045d81627b5c58bc2da53",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "CN=GlobalSign RootSign Partners CA, OU=RootSign Partners CA, O=GlobalSign nv,sa, C=BE",
      "ValidFrom": "2003-12-16 13:00:00",
      "ValidTo": "2014-01-27 11:00:00"
    },
    {
      "Signature": "a0422eb876a7427186404d464d5b26b0b074f93f89a87b7cb7f1c697e08239999d43fe60823642b55b878df55df4bbffa91044a871d3c7f12241f29aa4a5ec63fae5eb654a19309d8bc7b6fddc3fe16cfdd5521407fc6d24ccb3cc81a2c052f327b96d9e063dd8a849023269c7054294d0bbe3bba908c393501bdb846dc0ba1e5298659c1376bdb3d567292f1f7baa2c51a0fd854f263c48a38127a6feee7f7899c245cf9d1f527ed7958bfde1d020c3af7e51a22f663bab2dcf2d8e8c4d7d18392128fbdcae6d6581d0e0d7184be7b5f774d784e6522aac3b68fd3b4ab80154849132bb95d28e6330a69ece2396feab2eb86a8b74dcde21a114c2fbbf53af10",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Primary Object Publishing CA, CN=GlobalSign Primary Object Publishing CA",
      "ValidFrom": "1999-01-28 12:00:00",
      "ValidTo": "2014-01-27 11:00:00"
    },
    {
      "Signature": "649b07caaccc411e37ef6f349cb5e8ca48f9daeafaf7172e5cad193b7311ec5adbfd7b213161c092515bb166b07c64d8fe10b471a8bc9e75379c5f6ff2da0437b8ecc003e256b7785995581d7a7c3e18d74c32bdf91ee723457fdee08d65825b45fd64c66fc3d7ea12411d0c395ef696f8c3cd9e1fff51886976988b8eb42788821ad63c7aabb04eb73ee8d434d2c1a439533cb2747b15373054a6ebb924cc2f084b4364f14aaf8d9ce8546cb2dbdc3bb1c722849f558e72a8b2a8f6f0ff03c996ebab8273dabe45561936fdba6cbc71f0d3c7c376d7e4bce2a1a67200cfbdb200ed92aa39ab09d16e3953862ad43b517398b754e9972d9977ee123e3642257f",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "O=GlobalSign, CN=GlobalSign Time Stamping Authority, emailAddress=timestampinfo@globalsign.com",
      "ValidFrom": "2007-02-05 09:00:00",
      "ValidTo": "2014-01-27 09:00:00"
    },
    {
      "Signature": "11d45d8af43d0d9d7e4fa70071610b56b34caa70e1b2d1dec7886d1d897c2ba946e58b1f8e4cc26695911fe34d394ae31b70b7446edc068a4d6d25e89812dcbca0dd864eae8f81130540905a542529944acaf165b4ef0679dae7cb86f004c918dcee72b320015748dfe333e12ccd9c077f9447278d888d340ca67c5c20c17d07b3736b648c26d29bd7e87965a6a891a174862a050282c1847cf279cd3c2a2b0f99291eea8c8a1ab16aeaa266380e65e1add8c6c91f888d3976ee1782c4138d97ce6341e77af5b4b66c15c33813b3930b620688dde1447f10a950248b60dc05f75ba514b27b56720b96eabffc057090659e051ca4dd07af4b57dec639673bc574",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA",
      "ValidFrom": "2004-01-22 09:00:00",
      "ValidTo": "2014-01-27 10:00:00"
    },
    {
      "Signature": "13c56c5e077f3c57ff9b315f3fbd955425c679f92c31034d64694b56d95b976f7cf3f0d024657538639813701613f7a701f1c623e085866c0bf080945a75e87ce41e92b473bfc1b3a7b00bd31884cbcc09a35c9c4f3eb03a9c2d1bc404ef9737966fe5ecbaac6ab3d4e23cdf8b25e7acbc624531dda40a72e41bf8784301ccba3914de5d90aed85acf5eca46815133d5a60e5867d3d8665888169beeb11acaad91138421da9a6e20efda007428bac95ff34d5dc3da25692554ea44bcc39b29331cd63c961f8781c553d72a2733d42e197c08586ddb4e1999a9ea5ff39a9d8c513a5a5cbd2fa908359b54a7db351a521633343aa380046afdb4838cad90cf0c3a6596ec334e1826b849bbeb8192ff134d324b23c733e7b6716b15f69c80e6bcb76cbe41d5033a7133150050743b0e5df996aaed903eab134c809926bc38a5eb0236891db620be83ab10f8199ed76379d4aeb12f6136f94a4ba833c70e7241f9f1b1907eae46efde397b75a0411459041d42bc4788b8130e05fa1df0808dff70c677d84bdc460e231a72d5bfdefeaaae69583cfc5c46e4d5819a8b6e6559771a32a590a6b6649364fd0753c9a0de28ad2a6cc638d181ce98f54019e92c1743a4265fd3443053e41d02baa40a2f16dd7a60275242bbad98372897e4b8d27911e3108c48d5305d0a0c52def588ea8d1a2d67c9f4801484b7850cd16628a5c66f2461",
      "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
      "Subject": "C=BE, O=GlobalSign nv,sa, OU=Root CA, CN=GlobalSign Root CA",
      "ValidFrom": "2006-05-23 17:00:51",
      "ValidTo": "2016-05-23 17:10:51"
    }
  ],
  "CertificatesInfo": "",
  "Signer": [
    {
      "Issuer": "C=BE, O=GlobalSign nv,sa, OU=ObjectSign CA, CN=GlobalSign ObjectSign CA",
      "SerialNumber": "01000000000115372421a8"
    }
  ],
  "SignerInfo": ""
}
```

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/f0fd5bc6-9ebd-4eb0-93ce-9256a5b9abf9.yaml)

*last_updated:* 2023-05-23








{{< /column >}}
{{< /block >}}
