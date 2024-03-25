package saml

import (
	"encoding/xml"
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
