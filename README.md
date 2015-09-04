# paillier-encryption
Paillier cryptosystem in Racket. This is an interesting cryptosystem with homomorphic properties. The original paper is followed closely, except for key generation. 

During key generation, a generator (or base) is chosen. While the original specification uses a different, more complex method of choosing bases, the paper at https://www.cdc.informatik.tu-darmstadt.de/reports/TR/TI-02-04.pdf claims that:

>   The probability that a random element satisfies the key
>   condition is 1 - 1/n, and it is an overwhelming probability in the bit-length of the
>   public modulus n. Therefore we can use a random g of Z_n^2 as the public key.

Some implementations such as the one [here](https://github.com/NICTA/python-paillier/blob/master/phe/paillier.py#L58), use the base g = n + 1, which the above paper, if I'm understanding it correctly, calls the modified Paillier cryptosystem which is shown to be weaker than the original Paillier system being susceptible to a chosen ciphertext attack.

Usage
=====
* Generate your public-private key pair: `(define-values (public private) (paillier-generate-keys))`
* Encryption: `(define ct (paillier-encrypt-string "hello, dr. pascal paillier!" public))`
* Decryption: `(paillier-decrypt-string ct private)`
