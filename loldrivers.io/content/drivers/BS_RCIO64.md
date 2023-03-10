+++

description = "https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"
title = "BS_RCIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# BS_RCIO64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


BS_RCIO64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create BS_RCIO64.sys binPath=C:\windows\temp\BS_RCIO64.sys type=kernel
sc.exe start BS_RCIO64.sys
```

### Resources
<br>


<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>

<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>

<li><a href="https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Biostar.yar#L54">https://github.com/elastic/protections-artifacts/blob/932baf346cc8a743f1963ad3d4565b42ed17bebe/yara/rules/Windows_VulnDriver_Biostar.yar#L54</a></li>


<br>


##### Known Vulnerable Samples

| Filename: BS_RCIO64.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;BS_RCIO64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;BS_RCIO64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;BS_RCIO64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e&#39;}">d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e</a>|




### Binary Metadata
<br>

- binary: 
- Verified: 
- Date: 
- Publisher: 
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_rcio64.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
