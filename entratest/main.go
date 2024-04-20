package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	path := "https://tenant1.cookieai.test:8081/auth/saml/slo?SAMLResponse=fZJBT8MwDIX/SpV7mmRNsyTqKiG4TIILQxy4IKd1WUWXTHUq+PmUTRyQEEdbfn7vk90QnKazv09vacmPSOcUCYv93Y69oq3AuNDxTZCBaxmQ21ojd1ZXdQjaDDaw4hlnGlPcsU0pWbEnWnAfKUPMa0tuNJeaK/uknFdbX6tSW/nCijukPEbIF+Ux5zN5ITLGVabKLqX3EWEs8zrlrbRKwJKP4juqoCmtNvEn6lPasbHnIDfg7FaroXYhGNRKaWOdqrZYmd51sjMQ5OBY8XmaIvkL9Y4tc/QJaCQf4YTkc+cPNw/3fmXx5znl1KWJtc2Far5K/xcBEc7fVKz9oaJM5ccY+/RBZcQswFjTD9ueo6st11gPPGhruTE16MqCAtmLRlw92+Z6n0OGvNDv6jb1WDzDtOD/megy7Q9L1yERE20jfi8Vf/1A+wU=&Signature=lInEk5gHMixezv6xlcIBcScceeTzoI9qrw0Oeho8ARlTFjsiuk3J/ODzv3bo526Dl0rrqIBLC+mnRHWoy5hSbKHnpy6sR3WEQu6RRVp4d1Uf6kgGXfiZDM9eXMwjSYoTN3OhX3vNzlF2iXY8cWy06xIH3V9EwE8K4DYeheUP0+8jGRkvyWlKqKTLQSSem+Hp9LkuH8LcODXPleWTJD1TXpiYHbCszJxdTE2ueNW2UNiLB4M4zFSNahA+pXRWkyEnHMAxozq5ugpvDVomqX/9Gjc9135gzEVz/04EWtXLgBEa/PUKObheQpLEufqfeFUhGEQRlpHQ3u72CyvbxWAhxg==&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	u, _ := url.Parse(path)
	err := validateQuerySig(u.Query())
	panic(err)
}

var (
	// ErrInvalidQuerySignature is returned when the query signature is invalid
	ErrInvalidQuerySignature = errors.New("invalid query signature")
	// ErrNoQuerySignature is returned when the query does not contain a signature
	ErrNoQuerySignature = errors.New("query Signature or SigAlg not found")
)

// validateSig validation of the signature of the Redirect Binding in query values
// Query is valid if return is nil
//
// https://github.com/grafana/saml/blob/a6c0e9b86a4c064fa5a593a0575d8656d533e13e/service_provider_signed.go
func validateQuerySig(query url.Values) error {

	sig := query.Get("Signature")
	if sig == "" {
		return ErrNoQuerySignature
	}

	// Signature is base64 encoded
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	certs, err := getIDPSigningCerts()
	if err != nil {
		return err
	}

	// okta
	if err := validateQuerySigVariant(query, sigBytes, certs, false); err == nil {
		return nil
	}
	// entra
	if err := validateQuerySigVariant(query, sigBytes, certs, true); err == nil {
		return nil
	}
	return ErrInvalidQuerySignature
}

// validateSig validation of the signature of the Redirect Binding in query values
// Query is valid if return is nil
//
// https://github.com/grafana/saml/blob/a6c0e9b86a4c064fa5a593a0575d8656d533e13e/service_provider_signed.go
func validateQuerySigVariant(query url.Values, sigBytes []byte, certs []*x509.Certificate, includeBlankRelayState bool) error {
	alg := query.Get("SigAlg")
	if alg == "" {
		return ErrNoQuerySignature
	}

	respType := ""
	switch {
	case query.Get("SAMLResponse") != "":
		respType = "SAMLResponse"
	case query.Get("SAMLRequest") != "":
		respType = "SAMLRequest"
	default:
		return fmt.Errorf("no SAMLResponse or SAMLRequest found in query")
	}

	// Encode Query as standard demands.
	// query.Encode() is not standard compliant
	// as query encoding order matters
	res := respType + "=" + url.QueryEscape(query.Get(respType))

	relayState := query.Get("RelayState")
	if includeBlankRelayState || relayState != "" {
		res += "&RelayState=" + url.QueryEscape(relayState)
	}

	res += "&SigAlg=" + url.QueryEscape(alg)

	var (
		hashed  []byte
		hashAlg crypto.Hash
		sigAlg  x509.SignatureAlgorithm
	)

	// Hashed Query
	switch alg {
	case dsig.RSASHA256SignatureMethod:
		hashed256 := sha256.Sum256([]byte(res))
		hashed = hashed256[:]
		hashAlg = crypto.SHA256
		sigAlg = x509.SHA256WithRSA
	case dsig.RSASHA512SignatureMethod:
		hashed512 := sha512.Sum512([]byte(res))
		hashed = hashed512[:]
		hashAlg = crypto.SHA512
		sigAlg = x509.SHA512WithRSA
	case dsig.RSASHA1SignatureMethod:
		hashed1 := sha1.Sum([]byte(res)) // #nosec G401
		hashed = hashed1[:]
		hashAlg = crypto.SHA1
		sigAlg = x509.SHA1WithRSA
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", alg)
	}

	// validate signature
	for _, cert := range certs {
		// verify cert is RSA
		if cert.SignatureAlgorithm != sigAlg {
			continue
		}

		if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), hashAlg, hashed, sigBytes); err == nil {
			return nil
		}
	}

	return ErrInvalidQuerySignature
}

// getIDPSigningCerts returns the certificates which we can use to verify things
// signed by the IDP in PEM format, or nil if no such certificate is found.
func getIDPSigningCerts() ([]*x509.Certificate, error) {
	var certStrs []string

	certStrs = append(certStrs, "-----BEGIN CERTIFICATE-----\\nMIIC8DCCAdigAwIBAgIQQE1f3Kbw8YJEJNtk0u0HJDANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQD\\nEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNDAzMTEyMDMx\\nMzRaFw0yNzAzMTEyMTMxMzRaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQg\\nU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0Z8A1AvbYRl\\n/6xomGQrhDfL+mZEnTHZ/wfsEKeTRDS8vvi4pGbvscfP1EJt6oyx5aM+wfJQjtFbBBCOv7jrSWs+\\nGAHXmzKuEWpdWEhKA8olGxnhrSOZ615uRRwITspkGEgYsMaaUkV6AzI4Ej+yVvuLEcyHCNuzkNf8\\nu115U5E/g9yRQ+y7Tqo1yQty1jM1RW0hEVi+BWiBXbJCcbcu6Y/miARdoJ5sxId9gYhqlqkJawwl\\n0uFTRtGDu/eBO1VM+8+pkPinAtzFGk+8lZFORNNSSsAlPNaq7mdJzYkH7mvJDpWsDOF8vKu7lel6\\nJRlzUJN2T1zbKrN2Z4jWIi8fZQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAECOMtTQXxkq4JQh7h\\nLNu5rA9AxKs9aAK7pOZXRsxX2DWB/kiglTNvhe07E8uRsqVuZl7uEzXrE8GdgGmubdDC/pzdTyqc\\n5SFcTTG+L8GHS99M+WYvEYjwsgsvk6utGLYLT+Eytk8CFN5zVzVtsq/x1F/RJXcEc2fYSLYlsBqC\\nIoy0+BbIT7j89jSj+VNZCeSOUigR/heMdvdtgSYoMTdTmFFrYK/EfcKZCvyzHckUixNGY1lE1Thg\\nCrWdmzJZ2Pi3qJJoinLwlNFJDoSGnfDrxpkchvY1TpbQb/d8TfoG2GG+LpDu35OJu6kuasw6dw8m\\nakx/VNtsmKDjwQcoD+hR\\n-----END CERTIFICATE-----\n")
	certStrs = append(certStrs, "-----BEGIN CERTIFICATE-----\\nMIIC8DCCAdigAwIBAgIQXzpLPP73pKBCobXFPkIGbDANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQD\\nEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNDA0MTYxMzM5\\nNTBaFw0yNzA0MTYxMzM5NTBaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQg\\nU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuXwYN9Nq6tzq\\n3KmGE6Wb7gvR99ezuCCjqd0VljFtt1B57yiQf7o9JLqGWhRgSqlLgctKdqyISYCr4KsFQOwKDow+\\nu/2sJe4129xlI4f1vXC+uGByKvFwn4tRpIyhmYjRT4pnTSbLEJ4y2i34ZhUiic1s057AY78H5gX7\\nwCAS9EzWN5GE5vzSaQBlhjH8c7lfMi7NPjh3Y1QwEYhQfgGZ8cpceppYz4uaJ0JqOhz+NzHi7OBd\\n+Srw8LmgVvaZcoC+CAVDkNCJejfwckTz8Jo5ZK5ngih3ecXkfjoUs9sSArrd7O90EmWj+rx6NFwn\\nZ5SRLxg/Ek0hDeLL9r/zXGLk1QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQApGAHsj1+9fV2niS2V\\nMhd3IxBbogu/RQ/3eKuZLmmmQFtp/cBxLIT1wNazh5mXMvd4CYITdDJSmDzxdbBOApxwk7VdudQL\\n0VTzYO9NBrt88Lvmat+7L7M0QRw1y/iYF6oZLLNw6bkY0SwHgmoNQQVnup7kJT54/LzZJ8Fhh8mc\\nUc/uLzlTuWY7plmVSM7dicMhcYHGiSn2BPet9Infl0DV2O728G5cosVs0bTFX6s5g24H2ysbQSHF\\na3OuYpHdVZTX7fDlYC4otqC+JI1Y2x1PPx7b9wK2ezDl5u3kd+r9QViFXo6vxrVpv3Za9zl1oP8M\\nYeO8oWPlmQrEpPq2usJ8\\n-----END CERTIFICATE-----\n")
	if len(certStrs) == 0 {
		return nil, errors.New("cannot find any signing certificate in the IDP SSO descriptor")
	}

	certs := make([]*x509.Certificate, len(certStrs))

	// cleanup whitespace
	regex := regexp.MustCompile(`\s+`)
	for i, certStr := range certStrs {
		certStr = regex.ReplaceAllString(certStr, "")
		certBytes, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("cannot parse certificate: %s", err)
		}

		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs[i] = parsedCert
	}

	return certs, nil
}
