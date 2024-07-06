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
PeInjector                # Using CLI package executable
python3 -m PeInjector     # Using python module
python3 PeInjector.pyz    # Using python executable
PeInjector.exe            # Using python Windows executable

PeInjector test.exe 90    # Inject shellcode "NOP" (instruction 0x90) in test.exe
PeInjector -p test.exe 90 # Inject polymorphism shellcode to execute "NOP" (instruction 0x90) in test.exe
```

## Links

 - [Pypi](https://pypi.org/project/PeInjector)
 - [Github](https://github.com/user/PeInjector)
 - [Documentation](https://mauricelambert.github.io/info/python/security/PeInjector.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/PeInjector.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/PeInjector.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
