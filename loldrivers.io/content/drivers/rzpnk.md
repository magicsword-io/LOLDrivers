+++

description = ""
title = "rzpnk.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# rzpnk.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


A vulnerability exists in the latest version of Razer Synapse (v2.20.15.1104 as of the day of disclosure) which can be leveraged locally by a malicious application to elevate its privileges to those of NT_AUTHORITY\SYSTEM. The vulnerability lies in a specific IOCTL handler in the rzpnk.sys driver that passes a PID specified by the user to ZwOpenProcess. CVE-2017-9769.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create rzpnk.sys binPath=C:\windows\temp\rzpnk.sys type=kernel
sc.exe start rzpnk.sys
```

### Resources
<br>


<li><a href="https://github.com/nomi-sec/PoC-in-GitHub/blob/2a85c15ed806287861a7adec6545c85aec618e3b/2017/CVE-2017-9769.json#L13">https://github.com/nomi-sec/PoC-in-GitHub/blob/2a85c15ed806287861a7adec6545c85aec618e3b/2017/CVE-2017-9769.json#L13</a></li>

<li><a href="https://www.rapid7.com/db/modules/exploit/windows/local/razer_zwopenprocess/">https://www.rapid7.com/db/modules/exploit/windows/local/razer_zwopenprocess/</a></li>


<br>


##### Known Vulnerable Samples

| Filename: rzpnk.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;rzpnk.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;rzpnk.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;rzpnk.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63&#39;}">93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rzpnk.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
