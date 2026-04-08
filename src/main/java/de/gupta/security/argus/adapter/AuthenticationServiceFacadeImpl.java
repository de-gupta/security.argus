package de.gupta.security.argus.adapter;

import de.gupta.security.argus.application.service.AuthenticationService;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

final class AuthenticationServiceFacadeImpl implements AuthenticationServiceFacade
{
	private final AuthenticationService service;

	static AuthenticationServiceFacade create(final AuthenticationService service)
	{
		return new AuthenticationServiceFacadeImpl(service);
	}

	@Override
	public AuthenticationResult authenticate(final String token)
	{
		return service.authenticate(token);
	}

	private AuthenticationServiceFacadeImpl(final AuthenticationService service)
	{
		this.service = service;
	}
}