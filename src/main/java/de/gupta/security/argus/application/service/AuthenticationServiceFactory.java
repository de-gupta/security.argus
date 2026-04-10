package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;

public final class AuthenticationServiceFactory
{
	public static <ExternalIdentity, User> AuthenticationService create(
			final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
			final AuthenticationResultAdapter resultMapper)
	{
		// TODO: is this worth converting to Unfolding chain with a pair as intermediate and a final transform? would be more elegant and would save intermediate vars
		final AuthenticationService core = AuthenticationServiceImpl.create(configuration, resultMapper);
		final TokenAuthenticationCache cache = configuration.tokenAuthenticationCache();
		return CachingAuthenticationService.wrap(core, cache);
	}

	private AuthenticationServiceFactory()
	{
	}
}