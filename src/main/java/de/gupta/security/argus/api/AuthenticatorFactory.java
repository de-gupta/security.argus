package de.gupta.security.argus.api;

import java.util.Objects;

public final class AuthenticatorFactory
{
	public static <User> Authenticator create(final AuthenticatorConfiguration<User> configuration)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		throw new UnsupportedOperationException("Authenticator wiring is not implemented yet");
	}

	private AuthenticatorFactory()
	{
	}
}
