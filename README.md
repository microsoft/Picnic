# Picnic: Post Quantum Signatures 

The Picnic signature scheme is a family of digital signature schemes secure
against attacks by quantum computers.  This is a reference implementation of these schemes. 
The scheme and parameter sets are specified in the [Picnic Specification Document](https://github.com/Microsoft/Picnic/blob/master/spec).

A research papers describing the signature scheme are also available on the [Picnic website](https://microsoft.github.io/Picnic/).

The library is provided under the MIT License.  The authors are Steven Goldfeder and Greg Zaverucha.

The library builds a static library.  The public API surface is defined in [picnic.h](https://github.com/Microsoft/Picnic/blob/master/picnic.h).

## Linux Build Instructions

Tested on Ubuntu Linux, and the Windows Subsystem for Linux on Windows 10 (build 1709).

1. `make`  
This will build the project.  `make debug` will build with symbols and address
sanitizer.

2. `./example`  
Runs an example program that exercises the keygen, sign, verify and
serialization APIs.  See [example.c](https://github.com/Microsoft/Picnic/blob/master/example.c).


## Windows Build Instructions

Tested on Windows 10 with Visual Studio 2017.

Open the solution in `VisualStudio\picnic.sln`, and build the projects. 

The project `libpicnic` creates a `.lib` file, containing the functions defined `in picnic.h`.  
See the `example` project for a simple application that calls functions in the library.

### Acknowledgments
Thanks to Christian Paquin for providing feedback on picnic.h and for adding
support for a Windows build.


### Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
