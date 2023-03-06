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


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57">be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57</a></li>



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

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
