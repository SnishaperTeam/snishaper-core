package subscription

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestHTTPServer(t *testing.T, body []byte, userInfo string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userInfo != "" {
			w.Header().Set("Subscription-Userinfo", userInfo)
		}
		w.Header().Set("Content-Type", "text/yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestHTTPServerStatus(t *testing.T, status int, body []byte, userInfo string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userInfo != "" {
			w.Header().Set("Subscription-Userinfo", userInfo)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}
