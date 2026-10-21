package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sampleBody struct {
	Name string `json:"name"`
}

func decodeCase(t *testing.T, contentType, body string) *APIError {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	var dst sampleBody
	return DecodeJSON(httptest.NewRecorder(), req, &dst, 32<<10)
}

func TestDecode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int // 0 means success
	}{
		{"valid object", "application/json", `{"name":"a"}`, 0},
		{"malformed JSON", "application/json", `{"name":`, http.StatusBadRequest},
		{"missing content type", "", `{"name":"a"}`, http.StatusUnsupportedMediaType},
		{"wrong content type", "text/plain", `{"name":"a"}`, http.StatusUnsupportedMediaType},
		{"empty body", "application/json", "", http.StatusBadRequest},
		{"unknown field", "application/json", `{"name":"a","evil":1}`, http.StatusBadRequest},
		{"duplicate key", "application/json", `{"name":"a","name":"b"}`, http.StatusBadRequest},
		{"trailing garbage", "application/json", `{"name":"a"} x`, http.StatusBadRequest},
		{"second JSON value", "application/json", `{"name":"a"}{"name":"b"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := decodeCase(t, tc.contentType, tc.body)
			if tc.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %+v", err)
				}
				return
			}
			if err == nil || err.Status != tc.wantStatus {
				t.Fatalf("status = %+v, want %d", err, tc.wantStatus)
			}
		})
	}

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/x",
			strings.NewReader(`{"name":"`+strings.Repeat("x", 100)+`"}`))
		req.Header.Set("Content-Type", "application/json")
		var dst sampleBody
		err := DecodeJSON(httptest.NewRecorder(), req, &dst, 16)
		if err == nil || err.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized = %+v", err)
		}
	})
}
