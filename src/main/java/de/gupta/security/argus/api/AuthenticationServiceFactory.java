package de.gupta.security.argus.api;

import java.util.Objects;

// TODO: good pattern with inerface/factory and the to be written impl
public final class AuthenticationServiceFactory
{
	public static <User> AuthenticationService create(final AuthenticationConfiguration<User> configuration)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		throw new UnsupportedOperationException("Authentication service wiring is not implemented yet");
	}

	private AuthenticationServiceFactory()
	{
	}
}