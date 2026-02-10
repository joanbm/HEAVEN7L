HEAVEN7L
========
A program to run the "[heaven seven](https://www.pouet.net/prod.php?which=5)" 64k Windows demo by Exceed on 64-bit Linux via SDL.

![Obligatory screenshot](screenshot.png)

It uses 2 techniques, similar to [Wine](https://www.winehq.org/):
* **Translating Win32/DirectDraw/DirectAudio/etc. API calls to SDL.**
* **Jumping across 32-bit and 64-bit code via FAR CALL (WoW64 / "Heaven's Gate")**.

Why? Wine already exists!
-------------------------
This is just a project for the heck of it.

Quickstart
----------
You will need:
* A x86_64 computer
* Basic build tools (GCC, make, etc.), with 32-bit support
* CMake
* curl
* unzip
* SDL2 (64-bit version)

In Debian, you can use the following commands:
```sh
sudo apt update
sudo apt install build-essential cmake curl unzip libsdl2-dev
```

Then, build HEAVEN7L, download the "heaven seven" demo, and run it as follows:
```sh
cmake -B build && cmake --build build
./download_HEAVEN7W.sh
build/HEAVEN7L
```
