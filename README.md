![PeInjector Logo](https://mauricelambert.github.io/info/python/security/PeInjector_small.png "PeInjector logo")

# PeInjector

## Description

This python tool injects shellcode in Windows Program Executable to
backdoor it with optional polymorphism.

> Support x86 ans x64 architectures.

## Requirements

This package require:
 - python3
 - python3 Standard Library

## Installation

```bash
python3 -m pip install PeInjector
```

```bash
git clone "https://github.com/mauricelambert/PeInjector.git"
cd "PeInjector"
python3 -m pip install .
```

## Usages

### Command line

```bash
PeInjector                     # Using CLI package executable
python3 -m PeInjector          # Using python module
python3 PeInjector.pyz         # Using python executable
PeInjector.exe                 # Using python Windows executable

PeInjector test.exe 90         # Inject shellcode "NOP" (instruction 0x90) in test.exe
PeInjector -p test.exe 90      # Inject polymorphism shellcode to execute "NOP" (instruction 0x90) in test.exe

PeInjector -c test.exe calc    # Inject a shellcode to start the "calc" command line
PeInjector -c -p test.exe calc # Inject a polymorphic shellcode (obfuscated shellcode) to start the "calc" command line
```

### Python

```python
from PeInjector import *

shellcode = b"\x90" # NOP instruction

with open("target.exe", "rb") as target, open("backdoored_nop.exe", "wb") as backdoor:
    inject(target, backdoor, shellcode, polymorphism=False, command=True)

with open("target.exe", "rb") as target, open("backdoored_command_calc.exe", "wb") as backdoor:
    inject(target, backdoor, "calc", polymorphism=True, command=True)
```

## Detections

> Thanks to [VirusTotal](https://www.virustotal.com/) online, public and free service. I use it to test my backdoored files and compare antivirus solution.

My *pe-injector* is not sneaky, there is no antivirus bypass and contains a lot of IOC or suspicious content but only few antivirus detect backdoored files:

1. I sent 32 bits backdoored executable (compiled with gcc and stripped) on [virustotal](https://www.virustotal.com/gui/file/9ac447a91465402917f1b134923a1457728b9e4808fa273a8c71f6357cad4dc6) with a polymorphic shellcode execution but only 15 antivirus detect it as malicious. The following elements should be detected by antivirus:
    - Last section have *RWX* permissions (very very suspicious)
    - Last section name is `.inject` and contains *executable code* (PE characteristics) (very suspicious)
    - Entry point in the last section (very suspicious)
    - There are 2 section with *executable code* (PE characteristics) (suspicious)
2. I sent 64 bits backdoored executable (compiled with gcc and stripped) on [virustotal](https://www.virustotal.com/gui/file/762853dbad74578fb6e3eb8ba50ea7ceb284237415b537511bf7ed8acf51f334) with a polymorphic shellcode execution but only 7 antivirus detect it as malicious. The following elements should be detected by antivirus:
    - Last section have *RWX* permissions (it's very very suspicious)
    - Last section name is `.inject` and contains *executable code* (PE characteristics) (very suspicious)
    - Entry point in the last section (very suspicious)
    - There are 2 section with *executable code* (PE characteristics) (suspicious)
3. I sent 32 bits backdoored executable (compiled with gcc and stripped) on [virustotal](https://www.virustotal.com/gui/file/1b6d2690c03ff65cc43d44aa5ac77fe5be9566c19bd5d3fec9ff3a637d8b9237) with shellcode execution but only 13 antivirus detect it as malicious. The following elements should be detected by antivirus:
    - Last section name is `.inject` and contains *executable code* (PE characteristics) (very suspicious)
    - Entry point in the last section (very suspicious)
    - Last section *jump* on the first executable section (very suspicious)
    - There are 2 section with *executable code* (PE characteristics) (suspicious)
    - Last section have *RX* permissions (suspicious)
4. I sent 64 bits backdoored executable (compiled with gcc and stripped) on [virustotal](https://www.virustotal.com/gui/file/0780d9fa7dddf3c9c1a6da67f93f3916cf85f7f6e506a5b97861961b80ccbafa) with a polymorphic shellcode execution but only 4 antivirus detect it as malicious. The following elements should be detected by antivirus:
    - Last section name is `.inject` and contains *executable code* (PE characteristics) (very suspicious)
    - Entry point in the last section (very suspicious)
    - Last section *jump* on the first executable section (very suspicious)
    - There are 2 section with *executable code* (PE characteristics) (suspicious)
    - Last section have *RX* permissions (suspicious)

![VirusTotal screenshot for x86 backdoored PE with polymorphic shellcode](https://mauricelambert.github.io/info/python/security/virustotal_x86_backdoored_polymorphic.png "VirusTotal screenshot for x86 backdoored PE with polymorphic shellcode")

![VirusTotal screenshot for x86 backdoored PE with polymorphic shellcode](https://mauricelambert.github.io/info/python/security/virustotal_x64_backdoored_polymorphic.png "VirusTotal screenshot for x64 backdoored PE with polymorphic shellcode")

![VirusTotal screenshot for x86 backdoored PE with polymorphic shellcode](https://mauricelambert.github.io/info/python/security/virustotal_x86_backdoored.png "VirusTotal screenshot for x86 backdoored PE with shellcode")

![VirusTotal screenshot for x86 backdoored PE with polymorphic shellcode](https://mauricelambert.github.io/info/python/security/virustotal_x64_backdoored.png "VirusTotal screenshot for x64 backdoored PE with shellcode")

### Detection and antivirus solution comparaison

Only 3 antivirus detect all backdoored Program Executable:

 - Bkav Pro
 - SecureAge
 - Zoner

For all of theses antivirus solutions, there is only one interesting detection name, an antivirus solution should detect malicious files, block it and sent some basic informations to SOC analyst. For the least detected backdoored file we have the following detection names:

 - `BehavesLike.Win64.Kudj.lt` -> Windows 64 bits, detected as `Kudj.lt`, this detection name is very interesting because `Kudj` is a [file infector](https://www.fortiguard.com/encyclopedia/virus/10072870) but this detection name come from `Skyhigh` and this solution don't detect 32 bits backdoored files
 - `Probably Heur.ExeHeaderL` -> heuristic detection for suspicious headers, this detection is not very bad but some informations are missing
 - `W64.AIDetectMalware` -> Windows 64 bits, detected as malware by AI module but what is malicious ? No information about PE backdoored file... all techniques i use are documented on internet
 - `Malicious` -> What is malicious ? No information about PE backdoored file... all techniques i use are documented on internet

#### Best antivirus solution for PeInjector

The best solution to detect backdoored Program Executable is probably `Zoner` because it's one of the 3 solutions that detect 4 different tests and the detection name not really bad (with `Probably Heur.ExeHeaderL` a SOC analyst can analyze PE headers and identify the file as malicious file).

> I don't know if `Zoner` is a good antivirus, i don't say it's the best antivirus for general detection, but when i wrote theses lines it's probably the best antivirus to detect the PeInjector backdoored files. It's really a specific test. I never use `Zoner` antivirus solution.

## Links

 - [Pypi](https://pypi.org/project/PeInjector)
 - [Github](https://github.com/mauricelambert/PeInjector)
 - [Documentation](https://mauricelambert.github.io/info/python/security/PeInjector.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/PeInjector.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/PeInjector.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
