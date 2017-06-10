<h1>Certificate Templates</h1>
Here are the list of certificate templates we have used in our testing
frameworks.  This list contains 41 certificate templates (23 from templates
from the paper originally and some updated templates we just added).
All the certificates are self-signed and only be used for testing purpose.

Each template contains 3 files formatted as following:

 1. Certificate template identifier (.name) e.g., ```*.aaa.aaa```
 2. Certificate itself (.pem)
 3. Certificate private key (.key)

As the server identifier can present in common name (CN) and subject alternative name (SAN) (RFC 6125 https://tools.ietf.org/html/rfc6125), we also need to account those in testing. We format those in the .name file as following:
When server identifier locates in 

 - **common name**,  the .name file contain no indication, just the identifier e.g., ```*.aaa.aaa```
 - **subject alternative name DNS**, the .name file begins with ```DNS:``` e.g.,  ```DNS:*.aaa.aaa```
 - **subject alternative name IP address**, the .name file begins with ```IP:``` e.g., ```IP:111.111.111.111```
 - **subject alternative name email**, the .name file begins with ```email:``` e.g., ```email:AAA@aaa.aaa```

The certificate (.pem) can also opened with general certificate view program.
For example if you have openssl installed:
```
$ openssl x509 -in <certificate_file> -text
```
where ```<certificate_file>``` is name of certificate file (.pem).

Note that, by default, the testing framework itself can generate the
certificate from user-specified identifier (e.g., ```*.aaa.aaa```) on the fly
using GnuTLS (see:
        https://github.com/HVLearn/HVLearn/wiki/2.-Setting-up-and-understand-project-structure),
which is why it is required in the installation process.

