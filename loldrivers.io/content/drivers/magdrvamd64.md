+++

description = ""
title = "magdrvamd64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# magdrvamd64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


magdrvamd64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create magdrvamd64.sys binPath=C:\windows\temp\magdrvamd64.sys type=kernel
sc.exe start magdrvamd64.sys
```

### Resources
<br>


<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>


<br>


##### Known Vulnerable Samples

| Filename: magdrvamd64.sys |
|:---- |
|MD5: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;magdrvamd64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57&#39;}"></a>|
|SHA1: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;magdrvamd64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57&#39;}"></a>|
|SHA256: <a href="https://www.virustotal.com/gui/file/{&#39;Filename&#39;: &#39;magdrvamd64.sys&#39;, &#39;MD5&#39;: &#39;&#39;, &#39;SHA1&#39;: &#39;&#39;, &#39;SHA256&#39;: &#39;be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57&#39;}">be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57</a>|




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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/magdrvamd64.sys.yml)

*last_updated:* 2023-03-10


{{< /column >}}
{{< /block >}}
