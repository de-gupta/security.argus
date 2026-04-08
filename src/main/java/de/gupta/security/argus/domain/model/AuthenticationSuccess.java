package de.gupta.security.argus.domain.model;

import java.util.Objects;

public record AuthenticationSuccess(AuthenticatedIdentity identity) implements AuthenticationResult
{
	public static AuthenticationSuccess of(final AuthenticatedIdentity identity)
	{
		return new AuthenticationSuccess(identity);
	}

	public AuthenticationSuccess
	{
		identity = Objects.requireNonNull(identity, "identity must not be null");
	}
}
