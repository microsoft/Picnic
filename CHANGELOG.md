Version 4.0 -- 2018-12-05
* Update implementation to match spec version 2.0. See Appendix A for a summary
  of the changes. 

Version 3.0 -- 2018-09-06
* Fix deviations from specification. The KDF was missing the output length as
  input and the public key was incorrectly serialized. Note that this is breaking
  relative to the version submitted to the NIST PQC Project, and requires an
  update of the test vectors.

Version 2.1 -- 2018-09-05
* Small bug fixes, non-breaking changes
* Test and fix bug on big endian systems

Version 2.0 -- 2018-06-29

* Version submitted to the NIST PQC project.
* Implementation follows the spec, and differs significantly from the 1.0 version
* This implementation is now the "Reference Implementation", and is not optimized
* The "Optimized Implementation" is hosted at https://github.com/IAIK/Picnic

Version 1.0 -- 2017-05-04

* Initial release implementing an early version of Picnic described in the
  research paper http://eprint.iacr.org/2017/279.
