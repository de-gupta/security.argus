package de.gupta.security.argus.adapter;

import de.gupta.security.argus.application.service.AuthenticationService;

public final class AuthenticationServiceFacadeFactory
{
	public static AuthenticationServiceFacade create(final AuthenticationService service)
	{
		return AuthenticationServiceFacadeImpl.create(service);
	}

	private AuthenticationServiceFacadeFactory()
	{
	}
}