# PePatcher

PePatcher is a simple open source program to patch PE file with shellcode.
Installation
---
You can download the latest compiled exe by cliking [here](https://github.com/Loftven/PePatcher "Download compiled file").
Usage
---
To get a list of basic options use:
```cmd
./PePatcher -h
```
**Example**
```cmd
./PePatcher -f hello.exe -s d9eb9bd97424f431d2b27731c9648b71308b760c8b761c8b46088b7e208b36384f1875f35901d1ffe1608b6c24248b453c8b54287801ea8b4a188b5a2001ebe334498b348b01ee31ff31c0fcac84c07407c1cf0d01c7ebf43b7c242875e18b5a2401eb668b0c4b8b5a1c01eb8b048b01e88944241c61c3b20829d489e589c2688e4e0eec52e89fffffff894504bb7ed8e273871c2452e88effffff894508686c6c20416833322e64687573657230db885c240a89e656ff550489c250bba8a24dbc871c2452e85fffffff686f7858206861676542684d65737331db885c240a89e36858202020684d53462168726f6d20686f2c20666848656c6c31c9884c241089e131d252535152ffd031c050ff5508 -p 6
./PePatcher -f hexEditor.exe -n
```
If you use **msfvenom** you should encode your payload. There is simple command to help you:
```cmd
msfvenom -p windows/messagebox | od -A n -t x1 | sed \'s/ \*//g\' | tr -d \'\\n\'
``` 

# Warning
---
The program was developed for **training purposes** and use by **red teams**. The author is not responsible for its improper use.

Acknowledgments
---
- Thanks to the authors of the APT Warfare book and users of the [xss.is](https://xss.is "go to the forum") and [codeby](https://codeby.net "go to the forum") forums for their invaluable contribution to the development of information security.