; benchmark generated from python API
(set-info :status unknown)
(declare-fun maximum () Int)
(declare-fun nextcount () Int)
(declare-fun count () Int)
(assert
 (let (($x107 (>= count 0)))
(and (> maximum 0) $x107 (< count maximum) (= nextcount (+ count 1)) (> nextcount maximum))))
(check-sat)
