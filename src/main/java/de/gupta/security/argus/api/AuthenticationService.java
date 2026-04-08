package de.gupta.security.argus.api;

import de.gupta.security.argus.domain.model.AuthenticationResult;

// TODO: this is the ultimate api but very hard to find. rename this to Authenticator
public interface AuthenticationService
{
	AuthenticationResult authenticate(final String rawToken);
}