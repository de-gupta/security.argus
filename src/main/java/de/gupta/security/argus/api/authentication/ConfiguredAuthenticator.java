package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.adapter.AuthenticationServiceFacade;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

final class ConfiguredAuthenticator implements Authenticator
{
	private final AuthenticationServiceFacade serviceFacade;

	static Authenticator create(final AuthenticationServiceFacade serviceFacade)
	{
		return new ConfiguredAuthenticator(serviceFacade);
	}

	@Override
	public AuthenticationResult authenticate(final String token)
	{
		return serviceFacade.authenticate(token);
	}

	private ConfiguredAuthenticator(final AuthenticationServiceFacade serviceFacade)
	{
		this.serviceFacade = serviceFacade;
	}
}