package samlsp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func TestMiddlewareCreateIdpInitializedRedirectURI(t *testing.T) {
	googleToApp := func(relayState string) string {
		if relayState == "https://www.google.com/" {
			return "/app"
		}
		return ""
	}

	tests := []struct {
		name       string
		hook       func(string) string
		relayState string
		want       string
	}{
		{name: "no hook follows a local path", relayState: "/landing", want: "/landing"},
		{name: "no hook refuses an absolute URL", relayState: "https://www.google.com/", want: "/default"},
		{name: "hook maps the RelayState", hook: googleToApp, relayState: "https://www.google.com/", want: "/app"},
		{name: "hook empty result uses the default", hook: googleToApp, relayState: "https://evil.example/", want: "/default"},
		{name: "hook replaces the local path check", hook: googleToApp, relayState: "/landing", want: "/default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test := NewMiddlewareTest(t)
			test.Middleware.ServiceProvider.AllowIDPInitiated = true
			test.Middleware.CreateIdpInitializedRedirectURI = tt.hook

			form := url.Values{"RelayState": {tt.relayState}}
			req := httptest.NewRequest(http.MethodPost, "/saml2/acs", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			assert.NilError(t, req.ParseForm())

			rec := httptest.NewRecorder()
			test.Middleware.CreateSessionFromAssertion(rec, req, &saml.Assertion{}, "/default")
			assert.Check(t, is.Equal(http.StatusFound, rec.Code))
			assert.Check(t, is.Equal(tt.want, rec.Header().Get("Location")))
		})
	}
}

func TestNewSetsCreateIdpInitializedRedirectURI(t *testing.T) {
	test := NewMiddlewareTest(t)
	m, err := New(Options{
		URL:                             mustParseURL("https://15661444.ngrok.io/"),
		Key:                             test.Key,
		Certificate:                     test.Certificate,
		IDPMetadata:                     &saml.EntityDescriptor{},
		CreateIdpInitializedRedirectURI: func(string) string { return "/x" },
	})
	assert.NilError(t, err)
	assert.Check(t, is.Equal("/x", m.CreateIdpInitializedRedirectURI("")))
}
