# paillier-encryption
Paillier cryptosystem in Racket. This is an interesting cryptosystem with homomorphic properties. The [original paper](http://williams.comp.ncat.edu/signing/Pascal%20Paillier.pdf) is followed closely, except for key generation. 

During key generation, a generator (or base) is chosen. While the original specification uses a different, more complex method of choosing bases, this [paper](https://www.cdc.informatik.tu-darmstadt.de/reports/TR/TI-02-04.pdf) claims that:

>   The probability that a random element satisfies the key
>   condition is 1 - 1/n, and it is an overwhelming probability in the bit-length of the
>   public modulus n. Therefore we can use a random g of Z_n^2 as the public key.

Usage
=====
* Generate your public-private key pair: `(define-values (public private) (paillier-generate-keys))`
* Encryption: `(define ct (paillier-encrypt-string "hello, dr. pascal paillier!" public))`
* Decryption: `(paillier-decrypt-string ct private)`
