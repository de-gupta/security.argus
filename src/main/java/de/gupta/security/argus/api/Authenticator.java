package de.gupta.security.argus.api;

import de.gupta.security.argus.domain.model.AuthenticationResult;

public interface Authenticator
{
	AuthenticationResult authenticate(final String rawToken);
}
