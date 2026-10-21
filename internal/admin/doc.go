// Package admin contains the advanced administrative backend: the
// fixed permission registry, authorization transaction guards,
// append-only audit, bootstrap/recovery, account/session/quota
// administration, operational monitor actions and global queries.
//
// Authority model: USER has no global permission — own-resource
// capabilities are domain policy derived from identity, not roles.
// Admin capabilities come only from role assignments resolved
// server-side against the fixed catalog; a role shown in a client UI
// confers nothing by itself.
package admin
