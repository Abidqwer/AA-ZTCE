; benchmark generated from python API
(set-info :status unknown)
(declare-fun parent_rights () (_ BitVec 16))
(declare-fun requested_rights () (_ BitVec 16))
(assert
 (and (distinct (_ bv0 16) (bvand (bvand parent_rights requested_rights) (bvnot parent_rights))) true))
(check-sat)
