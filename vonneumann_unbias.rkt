#lang racket
(provide random-int)
; An implementation of the von Neumann unbiasing algorithm.
; The unbias procedure takes a pseudo-random bit generator and extracts entropy from the sequence of generated bits
; thereby creating a "more random" sequence.
; The catch here is that the sequence has to be a Bernoulli sequence. I.e. we can only unbias bent coins.
(define (extract-entropy bit-generator)
  (let ([x (bit-generator)]
        [y (bit-generator)])
    (cond [(or (and (= x 1) (= y 1))
               (and (= x 0) (= y 0)))
           (extract-entropy bit-generator)]
          [(and (= x 1) (= y 0)) 1]
          [else 0])))
          
(define (unbias bit-generator)
  (thunk (extract-entropy bit-generator)))

(define (bit-list->number bl)
  (string->number (foldr string-append "" (map number->string bl)) 2))

(define (random-int bit-generator num-bits)
  (bit-list->number
   (let ([random-bit (unbias bit-generator)])
     (let generate-bits ([bits-generated 0])
       (if (= bits-generated num-bits)
           null
           (cons (random-bit)  
                 (generate-bits (+ bits-generated 1))))))))
(module+ test
  (random-int (thunk (random 2)) 32))