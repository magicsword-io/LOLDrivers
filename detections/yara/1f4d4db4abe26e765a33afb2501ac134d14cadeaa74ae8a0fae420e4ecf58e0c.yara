
rule PUA_VULN_Driver_WindowsRWinDDKprovider_cpuzsys_WindowsRWinDDKdriver_urQw {
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - 17719a7f571d4cd08223f0b30f71b8b8.bin, 641243746597fbd650e5000d95811ea3.bin, 743c403d20a89db5ed84c874768b7119.bin, 4a85754636c694572ca9f440d254f5ce.bin, 549e5148be5e7be17f9d416d8a0e333e.bin, 2f8653034a35526df88ea0c62b035a42.bin, aa69b4255e786d968adbd75ba5cf3e93.bin"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "1f4d4db4abe26e765a33afb2501ac134d14cadeaa74ae8a0fae420e4ecf58e0c"
		hash = "c3e150eb7e7292f70299d3054ed429156a4c32b1f7466a706a2b99249022979e"
		hash = "2a9d481ffdc5c1e2cb50cf078be32be06b21f6e2b38e90e008edfc8c4f2a9c4e"
		hash = "8688e43d94b41eeca2ed458b8fc0d02f74696a918e375ecd3842d8627e7a8f2b"
		hash = "592f56b13e7dcaa285da64a0b9a48be7562bd9b0a190208b7c8b7d8de427cf6c"
		hash = "4d19ee789e101e5a76834fb411aadf8229f08b3ece671343ad57a6576a525036"
		hash = "60b163776e7b95e0c2280d04476304d0c943b484909131f340e3ce6045a49289"
		date = "2023-05-31"
		score = 50
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004300500055004900440020004400720069007600650072 } /* FileDescription CPUID Driver */
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00570069006e0064006f007700730020002800520029002000570069006e00200037002000440044004b002000700072006f00760069006400650072 } /* CompanyName Windows (R) Win 7 DDK provider */
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e003100360033003800350020006200750069006c0074002000620079003a002000570069006e00440044004b } /* FileVersion 6.1.7600.16385 built by: WinDDK */
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e00310036003300380035 } /* ProductVersion 6.1.7600.16385 */
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006300700075007a002e007300790073 } /* InternalName cpuz.sys */
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00570069006e0064006f007700730020002800520029002000570069006e00200037002000440044004b0020006400720069007600650072 } /* ProductName Windows (R) Win 7 DDK driver */
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006300700075007a002e007300790073 } /* OriginalFilename cpuz.sys */
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a90020004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } /* LegalCopyright © Microsoft Corporation. All rights reserved. */
	condition:
		all of them
}