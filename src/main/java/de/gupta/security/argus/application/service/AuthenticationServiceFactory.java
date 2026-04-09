package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;

public final class AuthenticationServiceFactory
{
	public static <ExternalIdentity, User> AuthenticationService create(
			final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
			final AuthenticationResultAdapter resultMapper)
	{
		return AuthenticationServiceImpl.create(configuration, resultMapper);
	}

	private AuthenticationServiceFactory()
	{
	}
}