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
(require math "vonneumann_unbias.rkt")

(struct paillier-public-key (n g))
(struct paillier-private-key (n g p q phi))
(struct paillier-ct (byte))

(define rand-int ((curry random-int) (thunk (random-integer 0 2))))

(define (random-prime-num bits)
  (let loop ([p (rand-int bits)])
    (if (prime? p)
        p
        (loop (rand-int bits)))))

; While the original specification uses a different, more complex method of choosing bases,
; the paper at https://www.cdc.informatik.tu-darmstadt.de/reports/TR/TI-02-04.pdf claims that
;   The probability that a random element satisfies the key
;   condition is 1 - 1/n, and it is an overwhelming probability in the bit-length of the
;   public modulus n. Therefore we can use a random g of Z_n^2 as the public key.
(define (choose-base n)
  (random-integer 1 (sqr n)))

(define (paillier-generate-keys)
  (let* ([p (random-prime-num 512)]
         [q (random-prime-num 512)]
         [n (* p q)]
         [g (choose-base n)]
         [l (lcm (sub1 p) (sub1 q))])
    (values
     (paillier-public-key n g)
     (paillier-private-key n g p q (lcm (sub1 p) (sub1 q))))))

(define (paillier-encrypt-byte byte public-key)
  (paillier-ct
   (let* ([g (paillier-public-key-g public-key)]
          [n (paillier-public-key-n public-key)]
          [n-sqrd (sqr n)]
          [r (random-integer 0 n)])
     (with-modulus n-sqrd
                   (mod* (modular-expt g byte n-sqrd)
                         (modular-expt r n n-sqrd))))))

(define (paillier-encrypt-string s public)
  (map (lambda (x) (paillier-encrypt-byte x public))
       (bytes->list (string->bytes/utf-8 s))))

(define (L x n)
  (/ (- x 1) n))

(define (paillier-decrypt-byte ct private-key)
  (let* ([n (paillier-private-key-n private-key)]
         [n-sqrd (sqr n)]
         [g (paillier-private-key-g private-key)]
         [phi (paillier-private-key-phi private-key)]
         [mu (modular-inverse (L (modular-expt g phi (sqr n)) n) n)]
         [u (modular-expt (paillier-ct-byte ct) phi n-sqrd)])
    (with-modulus n (mod* (L u n) mu))))

(define (paillier-decrypt-bytes b private)
  (map (lambda (x) (paillier-decrypt-byte x private))
       b))

(define (paillier-decrypt-string b private)
  (bytes->string/utf-8 (list->bytes (paillier-decrypt-bytes b private))))

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
