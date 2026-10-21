// Package monitor owns user-scoped monitor resources: validation,
// owned persistence under quota fencing, lifecycle transitions, and
// HTTP handlers. Every query and mutation carries an explicit owner
// scope — unguessable UUIDs are never the authorization boundary.
package monitor
