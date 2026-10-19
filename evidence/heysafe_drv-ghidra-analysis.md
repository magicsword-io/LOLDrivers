# HeySafe-X driver: static verification

Reviewed 2026-10-19. Submitted by [@rommel193911-sudo](https://github.com/rommel193911-sudo) in [LOLDrivers issue #468](https://github.com/magicsword-io/LOLDrivers/issues/468).

## Sample and method

| Field | Value |
| --- | --- |
| Filename | `heysafe_drv.sys` |
| Size | 95,312 bytes |
| SHA256 | `a188993dd8cac6628f97dfd390cfab8a9e510d581c39e32da66cbc4b559db27d` |
| SHA1 | `d4ecc7d58c8a7645be17d20901ecaa786fd6081c` |
| MD5 | `752d3a88a9f7d2fee7bd0df2dbcd7e69` |
| Version | `10.0.10011.16384` |
| Architecture | AMD64, Windows PE, Ghidra language `x86:LE:64:default` |
| Image base | `0x140000000` |
| Analysis | Ghidra 12.1.4 headless; 283 analyzed functions |

The file was imported into Ghidra using [MHaggis/codexghidra](https://github.com/MHaggis/codexghidra/tree/68feb9fd1b825ce23013542b8599ee21a481f7d5). The local service's health and program information were checked against the target hashes before analysis. Imports and cross-references were followed into initialization, object callbacks, the port connection/message handlers, the queued worker and the termination routine. Relevant decompilation was checked against disassembly. Addresses below are virtual addresses at the stated image base; inferred function names describe behavior rather than original symbols.

Hashes, PE/version resources, imports, Authenticode digest and certificate metadata were also extracted independently of Ghidra. The embedded digest matches the computed digest, and cryptographic signature verification succeeds when certificate time is ignored. This is not a current Windows trust or loading test.

No submitted driver, installer or PoC was executed or loaded.

## Confirmed control flow

| Finding | Evidence |
| --- | --- |
| Restricted minifilter port | Initialization at `0x140001de8` calls `FltBuildDefaultSecurityDescriptor` with `0x1f0001`, then creates the communication port. Connection callback `0x1400091e0` calls process validator `0x14000a6a8` and returns access denied on rejection. A full authorization-bypass assessment was not performed. |
| Caller-supplied termination target | Message handler `0x140009ad0` validates the header and payload lengths. Opcode `0x67` probes and reads a PID from the supplied payload, then calls `0x140006618`. Access to this handler depends on the port connection. |
| Queued process-tree termination | `0x140006618` stores the PID in an allocated work item and registers worker `0x140004d10`. Disassembly at `0x140006656` sets `EDX = 1` before the imported `ExQueueWorkItem` call at `0x140006669`: `DelayedWorkQueue`. |
| Descendant enumeration | Worker `0x140004d10` queries `SystemProcessInformation` (class 5), starts with the requested PID and collects descendant PIDs into a bounded 512-entry array. It then invokes the termination routine in collected order, beginning with the root. This is not bottom-up termination. |
| Termination and critical-flag clearing attempt | `0x140004c5c` requests process access `0x201`, attempts `ZwSetInformationProcess` with class `0x1d` (29), then calls `ZwTerminateProcess`. The return from flag clearing is not used to establish success. |
| Target exclusions | Guard `0x1400061cc` excludes PID 0/4, selected core Windows images (`lsass.exe`, `services.exe`, `csrss.exe`, `wininit.exe`, `smss.exe`, `winlogon.exe`) and registered HeySafe PIDs. The guard is called before queueing and before opening the termination target. |
| Object-callback registration | `0x1400022f4` registers `0x1400054c0` for process and thread handle operations using `ObRegisterCallbacks`. |
| Callback-triggered termination | Cross-references at `0x140005690` and `0x1400057e7` lead from the object callback into helper `0x1400084e0`. That helper compares the caller image name specifically with `werfault.exe`, then queues its PID at `0x1400085bc`, subject to state and IRQL checks. |

These are static findings for this exact file, not evidence of successful termination on every Windows version or against every target.

## Corrections to the submission

- **Analysis-tool counter-kill:** the cited helper selects `werfault.exe`. The names `taskmgr.exe`, `procexp.exe`, `procexp64.exe`, `windbg.exe`, `dbgx.shell.exe` and `devenv.exe` occur in an exception path elsewhere in the callback. Their presence does not substantiate the submitted claim that they are selected for termination.
- **Work queue and stack spoofing:** queue type 1 is `DelayedWorkQueue`, not `CriticalWorkQueue`. Asynchronous execution alone does not establish stack spoofing.
- **Crash prevention:** an attempted `ProcessBreakOnTermination` clear does not guarantee successful flag modification or crash-free termination.
- **Protected-process termination:** the kernel calls are present, but successful PPL/EDR termination was not reproduced.
- **Trusted-caller scenario:** injection into an accepted client or extraction of client keys was proposed by the submitter. Neither a complete bypass nor access by an arbitrary caller was demonstrated here.
- **Certificate theft:** the signer is `Shanxi Shiheng Rail Technology Co., Ltd`. Its certificate expires at `2013-05-28 23:59:59 UTC`, and no signing timestamp is present. Expiry and absent timestamp do not establish theft.

## Context and verification scope

The [public HeySafe-X site](https://heysafex.com/) presents the product as a Windows endpoint-protection beta. A [third-party software submission dated 2026-10-07](https://github.com/c1201y/ClassSoftwareHub/issues/159) also describes that product and links to the site. Neither source establishes that this exact sample was deployed maliciously. GitHub searches for the filename, product name and signer did not identify an additional abuse or bypass report beyond the original LOLDrivers submission; this is not an exhaustive search of the web.

The catalog retains the submission's malicious category as reported context. `Verified: TRUE` records that the sample identity and documented process-termination capabilities were statically verified. It does **not** mean that malicious intent, a generic authorization bypass, certificate theft, current Windows loading, HVCI compatibility or protected-process termination were established. Those claims require separate evidence.

The YAML supplies the required access conditions and leaves `LoadsDespiteHVCI: UNKNOWN`. The committed binary is stored through Git LFS. Its hash, pointer and size were checked, and both sample detection rules match it. Schema/catalog validation, API-export tests, YARA validation and website/browser CI are required before merge.
