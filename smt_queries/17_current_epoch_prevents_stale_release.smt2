; benchmark generated from python API
(set-info :status unknown)
(declare-fun snapshot_epoch () Int)
(declare-fun commit_epoch () Int)
(assert
 (let (($x137 (= commit_epoch snapshot_epoch)))
(and (> commit_epoch snapshot_epoch) $x137)))
(check-sat)
