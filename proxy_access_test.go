package main

// Tests for the gate that closes the proxy's own diagnostics endpoints. The PAC
// file has to stay reachable without credentials (iPadOS fetches it before any
// proxy exists), everything else defaults to closed.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelfPathAccessClassification(t *testing.T) {
	for _, p := range []string{"/proxy.pac", "/wpad.dat", "/welcome", "/favicon.ico"} {
		if got := selfPathAccess(p); got != selfPublic {
			t.Errorf("selfPathAccess(%q) = %v, want selfPublic — the iPad fetches this before it has a proxy", p, got)
		}
	}
	// Handlers that already authenticate themselves must not be double-gated.
	for _, p := range []string{"/settings", "/admin", "/admin/", "/admin/logs", "/admin/settings"} {
		if got := selfPathAccess(p); got != selfOwnAuth {
			t.Errorf("selfPathAccess(%q) = %v, want selfOwnAuth", p, got)
		}
	}
	for _, p := range []string{"", "/", "/status", "/logs", "/ws", "/geo-check", "/geo-status.json", "/geo-bench", "/block-check", "/metrics", "/anything-new"} {
		if got := selfPathAccess(p); got != selfNeedsAuth {
			t.Errorf("selfPathAccess(%q) = %v, want selfNeedsAuth (fail closed)", p, got)
		}
	}
}

func diagReq(remote, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://proxy.example"+path, nil)
	r.RemoteAddr = remote
	return r
}

func TestDiagAuthorized(t *testing.T) {
	prevUser, prevPass := adminUser, adminPass
	prevToken, prevOpen := diagTokenVal, diagOpen
	defer func() {
		adminUser, adminPass = prevUser, prevPass
		diagTokenVal, diagOpen = prevToken, prevOpen
	}()

	adminUser, adminPass = "admin", "s3cret"
	diagTokenVal, diagOpen = "", false

	withBasic := func(r *http.Request, user, pass string) *http.Request {
		r.SetBasicAuth(user, pass)
		return r
	}

	t.Run("allowed", func(t *testing.T) {
		cases := map[string]*http.Request{
			"deploy script curls 127.0.0.1":  diagReq("127.0.0.1:5555", "/geo-check"),
			"ipv6 loopback":                  diagReq("[::1]:5555", "/geo-check"),
			"admin credentials from outside": withBasic(diagReq("203.0.113.9:5555", "/geo-bench"), "admin", "s3cret"),
		}
		for name, r := range cases {
			rec := httptest.NewRecorder()
			if !diagAuthorized(rec, r) {
				t.Errorf("%s: refused (%d %s)", name, rec.Code, rec.Body.String())
			}
		}

		diagTokenVal = "tok-123"
		for name, r := range map[string]*http.Request{
			"bearer token":        bearerReq("203.0.113.9:5555", "/geo-check", "tok-123"),
			"token in the query":  diagReq("203.0.113.9:5555", "/geo-check?token=tok-123"),
			"token in the header": headerReq("203.0.113.9:5555", "/geo-check", "X-NetNinja-Token", "tok-123"),
		} {
			rec := httptest.NewRecorder()
			if !diagAuthorized(rec, r) {
				t.Errorf("%s: refused (%d %s)", name, rec.Code, rec.Body.String())
			}
		}

		diagOpen = true
		rec := httptest.NewRecorder()
		if !diagAuthorized(rec, diagReq("203.0.113.9:5555", "/geo-check")) {
			t.Error("DIAG_PUBLIC=1 must open the endpoint")
		}
	})

	t.Run("refused", func(t *testing.T) {
		diagTokenVal, diagOpen = "tok-123", false
		cases := map[string]*http.Request{
			"internet client, no credentials": diagReq("203.0.113.9:5555", "/geo-check"),
			"wrong password":                  withBasic(diagReq("203.0.113.9:5555", "/geo-check"), "admin", "nope"),
			"wrong user":                      withBasic(diagReq("203.0.113.9:5555", "/geo-check"), "root", "s3cret"),
			"wrong token":                     diagReq("203.0.113.9:5555", "/geo-check?token=nope"),
			"loopback behind a reverse proxy": proxyForwardedReq("127.0.0.1:5555", "/geo-check"),
			"loopback with X-Real-Ip":         realIPReq("127.0.0.1:5555", "/geo-check"),
			"loopback with Forwarded header":  forwardedHeaderReq("127.0.0.1:5555", "/geo-check"),
		}
		for name, r := range cases {
			rec := httptest.NewRecorder()
			if diagAuthorized(rec, r) {
				t.Errorf("%s: allowed, want 401", name)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: status = %d, want 401", name, rec.Code)
			}
			if rec.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s: no WWW-Authenticate challenge", name)
			}
		}
	})

	t.Run("admin credentials without ADMIN_PASS are never accepted", func(t *testing.T) {
		adminPass = ""
		rec := httptest.NewRecorder()
		if adminCredsOK(withBasic(diagReq("203.0.113.9:5555", "/geo-check"), "admin", "")) {
			t.Error("adminCredsOK accepted an empty configured password")
		}
		if diagAuthorized(rec, withBasic(diagReq("203.0.113.9:5555", "/geo-check"), "admin", "")) {
			t.Error("diagAuthorized allowed a client because both passwords were empty")
		}
	})
}

func bearerReq(remote, path, token string) *http.Request {
	r := diagReq(remote, path)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func headerReq(remote, path, key, value string) *http.Request {
	r := diagReq(remote, path)
	r.Header.Set(key, value)
	return r
}

func proxyForwardedReq(remote, path string) *http.Request {
	return headerReq(remote, path, "X-Forwarded-For", "203.0.113.9")
}

func realIPReq(remote, path string) *http.Request {
	return headerReq(remote, path, "X-Real-Ip", "203.0.113.9")
}

func forwardedHeaderReq(remote, path string) *http.Request {
	return headerReq(remote, path, "Forwarded", "for=203.0.113.9")
}
