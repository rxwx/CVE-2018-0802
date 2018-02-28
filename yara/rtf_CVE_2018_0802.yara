rule rtf_CVE_2018_0802 {
meta:
	author = "Rich Warren"
	ref = "http://www.freebuf.com/vuls/159789.html"
 strings:
	$header_rtf = "{\\rt" ascii nocase
 	$equation = { 45 71 75 61 74 69 6F 6E 2E 33 }
 	$header_and_shellcode = /03010[0-1]([0-9a-fA-F]){4}([0-9a-fA-F]+08)([0-9a-fA-F]{4})([0-9a-fA-F]{296})2500/ ascii nocase
 condition:
 	uint32be(0) == 0x7B5C7274 and all of them
 }
