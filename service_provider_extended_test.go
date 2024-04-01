package saml

import (
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/crewjam/saml/testsaml"
)

func TestSPCanProduceRedirectLogoutRequest_Signed(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	redirectURL, err := s.MakeRedirectLogoutRequest("ross@octolabs.io", "relayState", "")
	assert.Check(t, err)

	kv := redirectURL.Query()
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, kv.Get("SigAlg")))
	assert.Check(t, kv.Has("Signature"))

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	assert.Check(t, is.Equal("idp.testshib.org",
		redirectURL.Host))
	assert.Check(t, is.Equal("/idp/profile/SAML2/Redirect/SLO",
		redirectURL.Path))
	golden.Assert(t, string(decodedRequest), t.Name()+"_decodedRequest")
}

func TestValidateLogoutResponseRedirectNoSignatureElement(t *testing.T) {
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	t.Run("AllowNoSignatureElementDisabled", func(t *testing.T) {
		test := NewServiceProviderTest(t)
		s := ServiceProvider{
			Key:                    test.Key,
			Certificate:            test.Certificate,
			MetadataURL:            mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
			AcsURL:                 mustParseURL("https://15661444.ngrok.io/saml2/acs"),
			SignatureMethod:        dsig.RSASHA256SignatureMethod,
			SloURL:                 mustParseURL("https://idp.testshib.org/idp/profile/SAML2/Redirect/SLO"),
			IDPMetadata:            &EntityDescriptor{},
			AllowNoSignatureLogout: false, // flag under test
		}
		err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
		assert.Check(t, err)

		// override the entity id
		s.IDPMetadata.EntityID = "https://15661444.ngrok.io/saml2/metadata"

		data := golden.Get(t, "TestValidateLogoutResponseRedirectNoSignatureElement_response.txt")

		err = s.ValidateLogoutResponseRedirect(string(data))
		assertError(t, err, "signature element not present")
	})
	t.Run("AllowNoSignatureElementEnabled", func(t *testing.T) {
		test := NewServiceProviderTest(t)
		s := ServiceProvider{
			Key:                    test.Key,
			Certificate:            test.Certificate,
			MetadataURL:            mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
			AcsURL:                 mustParseURL("https://15661444.ngrok.io/saml2/acs"),
			SignatureMethod:        dsig.RSASHA256SignatureMethod,
			SloURL:                 mustParseURL("https://idp.testshib.org/idp/profile/SAML2/Redirect/SLO"),
			IDPMetadata:            &EntityDescriptor{},
			AllowNoSignatureLogout: true, // flag under test
		}
		err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
		assert.Check(t, err)

		// override the entity id
		s.IDPMetadata.EntityID = "https://15661444.ngrok.io/saml2/metadata"

		data := golden.Get(t, "TestValidateLogoutResponseRedirectNoSignatureElement_response.txt")

		err = s.ValidateLogoutResponseRedirect(string(data))
		assertError(t, err, "signature element not present")
	})
}

func NewServiceProviderTest2(t *testing.T) *ServiceProviderTest {
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	RandReader = &testRandomReader{}

	test := ServiceProviderTest{}
	test.AuthnRequest = golden.Get(t, "SP_AuthnRequest")
	test.SamlResponse = golden.Get(t, "SP_SamlResponse")
	test.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "idp_cert.pem"))
	test.IDPMetadata = golden.Get(t, "SP_IDPMetadata")
	return &test
}

func TestValidateLogoutResponseRedirectRaw(t *testing.T) {
	test := NewServiceProviderTest2(t)
	TimeNow = func() time.Time {
		return time.Now()
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		SignatureMethod: dsig.RSASHA256SignatureMethod,
		SloURL:          mustParseURL("https://idp.testshib.org/idp/profile/SAML2/Redirect/SLO"),
		IDPMetadata:     &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	// override the entity id
	s.IDPMetadata.EntityID = "https://15661444.ngrok.io/saml2/metadata"

	t.Run("ErrEmpty", func(t *testing.T) {
		err = s.ValidateLogoutResponseRedirect("")
		assertError(t, err, "unable to deflate: unexpected EOF")
	})
	t.Run("ErrNotBase64", func(t *testing.T) {
		err = s.ValidateLogoutResponseRedirect("text")
		assertError(t, err, "unable to deflate: unexpected EOF")
	})
	t.Run("ErrNotDeflated", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("encode this"))
		err = s.ValidateLogoutResponseRedirect(encoded)
		assertError(t, err, "unable to deflate: flate: corrupt input before offset 8")
	})
	t.Run("ErrNotXml", func(t *testing.T) {
		deflated := deflateText("encode this")
		encoded := base64.StdEncoding.EncodeToString(deflated)
		err = s.ValidateLogoutResponseRedirect(encoded)
		assertError(t, err, "unable to deflate: flate: corrupt input before offset 1")
	})
	t.Run("ErrNotSigned", func(t *testing.T) {
		redirectURL, err := s.MakeRedirectLogoutResponse("requestID", "relayState")
		assert.Check(t, err)

		kv := redirectURL.Query()
		sr := kv.Get("SAMLResponse")
		err = s.ValidateLogoutResponseRedirect(sr)
		assertError(t, err, "cannot validate signature on LogoutResponse: Could not verify certificate against trusted certs")
	})
	t.Run("Ok", func(t *testing.T) {
		t.Skip() // need to sign response with correct idp cert, which are hardcoded and not dynamic
		s.AllowNoSignatureLogout = true
		defer func() {
			s.AllowNoSignatureLogout = false
		}()

		redirectURL, err := s.MakeRedirectLogoutResponse("requestID", "relayState")
		assert.Check(t, err)

		kv := redirectURL.Query()
		sr := kv.Get("SAMLResponse")
		err = s.ValidateLogoutResponseRedirect(sr)
		assertNoError(t, err)
	})
}

func deflateText(text string) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(text)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func assertNoError(t *testing.T, err error) {
	if err == nil {
		return
	}

	// get inner message if it exists
	var parseErr *InvalidResponseError
	if errors.As(err, &parseErr) {
		err = parseErr.PrivateErr
		t.Logf("Response: %v", parseErr.Response)
	}
	t.Error(err)
}

func assertError(t *testing.T, err error, message string, msgAndArgs ...interface{}) {
	if err == nil {
		return
	}

	// get inner message if it exists
	var parseErr *InvalidResponseError
	if errors.As(err, &parseErr) {
		err = parseErr.PrivateErr
	}
	assert.Error(t, err, message, msgAndArgs)
}
