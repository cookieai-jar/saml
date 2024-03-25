package samlsp

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/crewjam/saml"
)

func NewCustomMiddlewareTest(t *testing.T, moreOpts ...func(*Options)) *MiddlewareTest {
	test := MiddlewareTest{}
	saml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Mon Dec 1 01:57:09.123456789 UTC 2015")
		return rv
	}
	jwt.TimeFunc = saml.TimeNow
	saml.Clock = dsig.NewFakeClockAt(saml.TimeNow())
	saml.RandReader = &testRandomReader{}

	test.AuthnRequest = golden.Get(t, "authn_request.url")
	test.SamlResponse = golden.Get(t, "saml_response.xml")
	test.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	test.IDPMetadata = golden.Get(t, "idp_metadata.xml")

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(test.IDPMetadata, &metadata); err != nil {
		panic(err)
	}

	opts := Options{
		URL:         mustParseURL("https://15661444.ngrok.io/"),
		Key:         test.Key,
		Certificate: test.Certificate,
		IDPMetadata: &metadata,
	}
	for _, opt := range moreOpts {
		opt(&opts)
	}

	var err error
	test.Middleware, err = New(opts)
	if err != nil {
		panic(err)
	}

	sessionProvider := DefaultSessionProvider(opts)
	sessionProvider.Name = "ttt"
	sessionProvider.MaxAge = 7200 * time.Second

	sessionCodec := sessionProvider.Codec.(JWTSessionCodec)
	sessionCodec.MaxAge = 7200 * time.Second
	sessionProvider.Codec = sessionCodec

	test.Middleware.Session = sessionProvider

	test.Middleware.ServiceProvider.MetadataURL.Path = "/saml2/metadata"
	test.Middleware.ServiceProvider.AcsURL.Path = "/saml2/acs"
	test.Middleware.ServiceProvider.SloURL.Path = "/saml2/slo"

	var tc JWTSessionClaims
	if err := json.Unmarshal(golden.Get(t, "token.json"), &tc); err != nil {
		panic(err)
	}
	test.expectedSessionCookie, err = sessionProvider.Codec.Encode(tc)
	if err != nil {
		panic(err)
	}

	return &test
}

func TestMiddlewareIdpInitializedRelayState(t *testing.T) {
	t.Run("OriginalBehavior", func(t *testing.T) {
		test := NewCustomMiddlewareTest(t, func(options *Options) {
			options.AllowIDPInitiated = true
		})
		v := &url.Values{}
		v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
		v.Set("RelayState", "https://www.google.com/")
		req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp := httptest.NewRecorder()
		test.Middleware.ServeHTTP(resp, req)
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))

		assert.Check(t, is.Equal("https://www.google.com/", resp.Header().Get("Location")))
		assert.Check(t, is.DeepEqual([]string{
			"ttt=" + test.expectedSessionCookie + "; " +
				"Path=/; Domain=15661444.ngrok.io; Max-Age=7200; HttpOnly; Secure"},
			resp.Header()["Set-Cookie"]))
	})
	t.Run("NoRedirect", func(t *testing.T) {
		test := NewCustomMiddlewareTest(t, func(options *Options) {
			options.AllowIDPInitiated = true
			options.CreateIdpInitializedRedirectURI = func(relayState string) string {
				return "/"
			}
		})
		v := &url.Values{}
		v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
		v.Set("RelayState", "https://www.google.com/")
		req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp := httptest.NewRecorder()
		test.Middleware.ServeHTTP(resp, req)
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))

		assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
		assert.Check(t, is.DeepEqual([]string{
			"ttt=" + test.expectedSessionCookie + "; " +
				"Path=/; Domain=15661444.ngrok.io; Max-Age=7200; HttpOnly; Secure"},
			resp.Header()["Set-Cookie"]))
	})
}
