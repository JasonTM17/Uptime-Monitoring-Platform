package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

// ErrCode is the public, frozen error-code catalog. Clients may switch on
// these strings; new codes are additive only.
type ErrCode string

const (
	ErrBadRequest    ErrCode = "BAD_REQUEST"
	ErrNotFound      ErrCode = "NOT_FOUND"
	ErrMethod        ErrCode = "METHOD_NOT_ALLOWED"
	ErrPayloadLarge  ErrCode = "PAYLOAD_TOO_LARGE"
	ErrUnsupported   ErrCode = "UNSUPPORTED_MEDIA_TYPE"
	ErrUnprocessable ErrCode = "UNPROCESSABLE_ENTITY"
	ErrInternal      ErrCode = "INTERNAL"
)

// APIError carries a safe client-facing failure.
type APIError struct {
	Status int
	Code   ErrCode
	Msg    string
}

func (e *APIError) Error() string { return e.Msg }

// WriteJSON renders the success envelope {"data": ...}.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// WriteError renders the error envelope {"error":{code,message},"request_id":...}.
// message must be safe for clients — never echo internals, SQL, or values.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code ErrCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":      map[string]any{"code": string(code), "message": msg},
		"request_id": RequestIDFromContext(r.Context()),
	})
}

// DecodeJSON bounds the body BEFORE any decode allocation, enforces the
// JSON media type, rejects unknown fields, first-level duplicate keys, and
// any trailing content after the single JSON value. Duplicate-key
// semantics: a repeated first-level object key is a 400, not a last-wins
// silently-accepted body.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) *APIError {
	ct := r.Header.Get("Content-Type")
	mt, _, mtErr := mime.ParseMediaType(ct)
	if mtErr != nil || mt != "application/json" {
		return &APIError{http.StatusUnsupportedMediaType, ErrUnsupported, "content type must be application/json"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &APIError{http.StatusRequestEntityTooLarge, ErrPayloadLarge, "request body too large"}
		}
		return &APIError{http.StatusBadRequest, ErrBadRequest, "could not read request body"}
	}
	if len(body) == 0 {
		return &APIError{http.StatusBadRequest, ErrBadRequest, "request body required"}
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return &APIError{http.StatusBadRequest, ErrBadRequest, "invalid JSON body"}
	}
	if dec.More() {
		return &APIError{http.StatusBadRequest, ErrBadRequest, "request body must contain a single JSON value"}
	}
	if dup, ok := firstLevelDuplicate(body); ok {
		return &APIError{http.StatusBadRequest, ErrBadRequest, fmt.Sprintf("duplicate key %q in body", dup)}
	}
	return nil
}

// firstLevelDuplicate reports the first repeated key of a top-level JSON
// object. Non-object bodies never have duplicates.
func firstLevelDuplicate(body []byte) (string, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil {
		return "", false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", false
	}
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", false
		}
		key, _ := keyTok.(string)
		if _, dup := seen[key]; dup {
			return key, true
		}
		seen[key] = struct{}{}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", false
		}
	}
	return "", false
}
