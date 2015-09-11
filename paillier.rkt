#lang racket
(provide (struct-out paillier-public-key)
         (struct-out paillier-private-key)
         (struct-out paillier-ct)
         paillier-generate-keys
         paillier-encrypt-byte
         paillier-decrypt-byte
         paillier-decrypt-bytes
         paillier-decrypt-string
         paillier-encrypt-string)
(require math)

(struct paillier-public-key (n g))
(struct paillier-private-key (n g p q lambda))
(struct paillier-ct (byte))

(define (random-prime-num bits)
  (random-prime (expt 2 bits)))

; While the original specification uses a different, more complex method of choosing bases,
; the paper at https://www.cdc.informatik.tu-darmstadt.de/reports/TR/TI-02-04.pdf claims that:
;   The probability that a random element satisfies the key
;   condition is 1 - 1/n, and it is an overwhelming probability in the bit-length of the
;   public modulus n. Therefore we can use a random g of Z_n^2 as the public key.
(define (choose-base n)
  (random-integer 1 (sqr n)))

(define prime-bits 512)
(define (paillier-generate-keys)
  (let* ([p (random-prime-num prime-bits)]
         [q (random-prime-num prime-bits)]
         [n (* p q)]
         [g (choose-base n)]
         [l (lcm (sub1 p) (sub1 q))]
         [pub (paillier-public-key n g)]
         [priv (paillier-private-key n g p q (lcm (sub1 p) (sub1 q)))])
    ;the idea here is to remove any sensitive data from memory if we don't need it anymore
    (collect-garbage)
    (values pub priv)))

;the optional argument is inelegant, but collecting garbage after every byte is SLOW, so we need a way to turn it off
(define (paillier-encrypt-byte byte public-key [collect-garbage? #t])
  (let ([ct (paillier-ct
   (let* ([g (paillier-public-key-g public-key)]
          [n (paillier-public-key-n public-key)]
          [n-sqrd (sqr n)]
          [r (random-integer 0 n)])
     (with-modulus n-sqrd
                   (mod* (modular-expt g byte n-sqrd)
                         (modular-expt r n n-sqrd)))))])
    ;the idea here is to remove any sensitive data from memory if we don't need it anymore
    (when collect-garbage?
      (collect-garbage))
    ct))


(define (paillier-encrypt-bytes b public)
  (let ([ct-bytes (map (lambda (a-byte) (paillier-encrypt-byte a-byte public #f))
                       (bytes->list b))])
    (collect-garbage)
    ct-bytes))

(define (paillier-encrypt-string s public)
  (paillier-encrypt-bytes (string->bytes/utf-8 s) public))

(define (L x n)
  (/ (- x 1) n))

; yes the optional argument stinks -- see the comment for paillier-encrypt-byte
(define (paillier-decrypt-byte ct private-key [collect-garbage? #t])
  (let* ([n (paillier-private-key-n private-key)]
         [n-sqrd (sqr n)]
         [g (paillier-private-key-g private-key)]
         [lambda (paillier-private-key-lambda private-key)]
         [mu (modular-inverse (L (modular-expt g lambda (sqr n)) n) n)]
         [u (modular-expt (paillier-ct-byte ct) lambda n-sqrd)]
         [pt (with-modulus n (mod* (L u n) mu))])
    (when collect-garbage?
      (collect-garbage))
    pt))

(define (paillier-decrypt-bytes b private)
  (let ([pt-bytes (list->bytes (map (lambda (a-byte) (paillier-decrypt-byte a-byte private #f))
                                    b))])
    (collect-garbage)
    pt-bytes))

(define (paillier-decrypt-string b private)
  (bytes->string/utf-8 (paillier-decrypt-bytes b private)))

(module+ test
  (require rackunit)
  (define-values (public private) (paillier-generate-keys))
  (check-equal? (paillier-decrypt-byte (paillier-encrypt-byte 255 public) private) 255)
  (check-equal? (paillier-decrypt-byte (paillier-encrypt-byte 1 public) private) 1)
  (check-equal? (paillier-decrypt-byte (paillier-encrypt-byte 0 public) private) 0)
  (check-equal? (paillier-decrypt-byte (paillier-encrypt-byte 64 public) private) 64)
  (check-equal? (paillier-decrypt-byte (paillier-encrypt-byte 128 public) private) 128)
  (check-equal? (paillier-decrypt-string (paillier-encrypt-string "hello, dr. pascal paillier!" public) private)
                "hello, dr. pascal paillier!"))
