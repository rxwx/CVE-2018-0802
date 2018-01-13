# CVE-2018-0802

- CVE-2018-08022:
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0802

- MITRE CVE-2018-0802:
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0802

- 0patch exploitation and patch video:
https://www.youtube.com/watch?v=XU-U4K270Z4

- Qihoo 360 blog post
http://www.freebuf.com/vuls/159789.html

- Checkpoint blog (brute-force ASLR bypass)
https://research.checkpoint.com/another-office-equation-rce-vulnerability

# packager_exec CVE-2018-0802

This repo contains a Proof of Concept exploit for CVE-2018-0802. To get round the limited command length allowed, the exploit uses the Packager OLE object to drop an embedded payload into the %TMP% directory, and then executes the file using a short command via a WinExec call, such as:  ```cmd.exe /c%TMP%\file.exe```.


## Usage

```python
packager_exec_CVE-2018-0802.py -e executable_path -o output_file_name
```

Add the -d option to exploit both CVE-2017-11882 and CVE-2018-0802 in the same document.

## Detection

I've added a Yara rule to detect this specific variant of the exploit as used itw. Please note that this can be easily bypassed and may need tweaking. Happy to take PR's for better ones ;)

# Greetz

This exploit is based heavily on the prior work already done by Embedi on CVE-2017-11882. I take no credit for the great work already achieved by those mentioned here.

Kudos also goes out to the many discoverers:

- bee13oy of Qihoo 360 Vulcan Team
- zhouat of Qihoo 360 Vulcan Team
- Liang Yin of Tencent PC Manager
- Luka Treiber of 0patch Team - ACROS Security
- Netanel Ben Simon and Omer Gull of Check Point Software Technologies
- Yang Kang, Ding Maoyin and Song Shenlei of Qihoo 360 Core Security (@360CoreSec)
- Yuki Chen of Qihoo 360 Vulcan Team
- Zhiyuan Zheng

# Sample exploit for CVE-2018-0802 (starting calc.exe as payload)

`example` folder holds an .rtf file which exploits CVE-2018-0802 vulnerability and runs calculator in the system.