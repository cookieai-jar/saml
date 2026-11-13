package samlsp

// idpInitiatedRedirectURI returns where to send the user after an IdP-initiated
// login, or "" to use the default redirect URI.
func (m *Middleware) idpInitiatedRedirectURI(relayState string) string {
	if m.CreateIdpInitializedRedirectURI != nil {
		return m.CreateIdpInitializedRedirectURI(relayState)
	}
	if isLocalRedirect(relayState) {
		return relayState
	}
	return ""
}
