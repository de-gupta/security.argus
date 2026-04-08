package de.gupta.security.argus.domain.model.authentication;

import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;

public record AuthenticationSuccess(AuthenticatedIdentity identity) implements AuthenticationResult
{
	public static AuthenticationSuccess of(final AuthenticatedIdentity identity)
	{
		return new AuthenticationSuccess(identity);
	}
}