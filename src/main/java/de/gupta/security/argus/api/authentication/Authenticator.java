package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

public interface Authenticator
{
	AuthenticationResult authenticate(final String token);
}