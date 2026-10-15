; benchmark generated from python API
(set-info :status unknown)
(declare-fun nextcount () Int)
(declare-fun count () Int)
(declare-fun maximum () Int)
(assert
 (let (($x107 (>= count 0)))
(let (($x154 (= maximum 16)))
(and $x154 $x107 (< count maximum) (= nextcount (+ count 1)) (> nextcount 16)))))
(check-sat)
