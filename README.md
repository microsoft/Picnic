# Picnic: Post Quantum Signatures 

The Picnic and Fish signature schemes are digital signature schemes secure
against attacks by quantum computers.  This is a reference implementation of these schemes, 
associated with the paper:

  **Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives**  
  Melissa Chase and David Derler and Steven Goldfeder and Claudio Orlandi and
  Sebastian Ramacher and Christian Rechberger and Daniel Slamanig and Greg
  Zaverucha   
  *Cryptology ePrint Archive: Report 2017/279*   
  <http://eprint.iacr.org/2017/279>   

The library is provided under the MIT License.  The authors are Steven Goldfeder and Greg Zaverucha.

## Linux Build Instructions

Tested on Ubuntu Linux

1. Install Dependencies:   
   `sudo apt-get install libssl-dev libm4ri-dev`  
will install  
 - `libssl-dev`, OpenSSL (https://openssl.org), for AES, SHA-256 and RNG implementations  
 - `libm4ri-dev`, M4RI (https://github.com/malb/m4ri), for precomputing LowMC constants   

2. `make matrices`  
This will build the program 'preprocessMatrices'

3. `./preprocessMatrices`  
This will create precomputed data required to implement LowMC in the directory "data". 
It only needs to be run once.

4. `make`  
This will build the project.  `make debug` will build with symbols and address
sanitizer.  `make avx` will build with AVX2 support

5. `./benchmark_lowmc`  
Runs the benchmark program

6. `./example`  
Runs an example program that exercises the keygen, sign and verify APIs.  See example.c.


## Windows Build Instructions

Tested on Windows 10 with Visual Studio 2015.

Open the solution in `VisualStudio\pqzk.sln`, build the projects. 

In order to use the library, the folder "data" must contain the precomputed
data (as described in step 3 of the Linux instructions). The preprocessMatrices
program is not built on Windows, because of the m4ri dependency.  One way to
create the precomputed data on Windows is using the Linux susbsytem for
Windows, following the Linux instructions above. 

Picnic depends on OpenSSL for AES, SHA-256 and random number generation.  A
build of OpenSSL (x64) for Windows is included.  To replace it with another
version, 
Build the OpenSSL static library,  and copy the following files resulting
from the Windows built of OpenSSL into the VisualStudio folder.
   - include\openssl\*
   - lib\libeay32.lib
For instructions on how to build OpenSSL for Windows, follow the
instructions from
https://github.com/openssl/openssl/blob/OpenSSL_1_0_2-stable/INSTALL.W64.


### Acknowledgments
Thanks to Christian Paquin for providing feedback on picnic.h and for adding
support for a Windows build


### Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
