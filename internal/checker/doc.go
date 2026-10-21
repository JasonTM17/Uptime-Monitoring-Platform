// Package checker performs bounded, policy-checked outbound HTTP
// observations of monitor targets. It owns the whole boundary between
// "we tried to reach the target" and "here is typed evidence": DNS
// validation, pinned dialing, TLS verification, body/deadline bounds
// and outcome classification. It knows nothing about schedulers,
// databases, or notifications — an Observation is its only product.
package checker
