; benchmark generated from python API
(set-info :status unknown)
(declare-fun revoked_commit () Bool)
(declare-fun authorized_start () Bool)
(assert
 (and authorized_start revoked_commit (not revoked_commit)))
(check-sat)
