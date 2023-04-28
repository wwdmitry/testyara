rule bxlarst
{
	//Input TP Rate:
	//2/3
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 2 files
		$x0 = { 78 79 2E 64 6C 6C 00 00 } //This might be a string? Looks like:xy.dll
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x1 = { 00 53 AC C8 5B E0 C3 E3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x2 = { 52 0E 0D E0 C3 E3 2C 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 2 files
		$x3 = { A0 14 32 00 A0 B8 0E 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x4 = { 00 23 C0 BC C8 5F FF D8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x5 = { 38 5D FC 74 44 8B 4D F8 } //This might be a string? Looks like:8]tDM

		condition:
(3 of ($x0,$x1,$x2,$x3,$x4,$x5) )}