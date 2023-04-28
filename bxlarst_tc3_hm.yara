rule bxlarst
{
	//Input TP Rate:
	//2/3
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 2 files
		$x0 = { 78 79 2E 64 6C 6C 00 00 } //This might be a string? Looks like:xy.dll
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 2 files
		$x1 = { 00 A0 14 32 00 A0 B8 0E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x2 = { 52 0E 0D E0 C3 E3 2C 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x3 = { C8 FF 5B 5F 5E 5D C3 88 } //This might be a string? Looks like:[_^]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x4 = { 3D A1 D4 C6 5F FF D8 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x5 = { 8F B2 09 18 32 D9 01 3A } 

		condition:
(3 of ($x0,$x1,$x2,$x3,$x4,$x5) )}