package de.gupta.security.argus.application.service;

public final class AuthenticationResultMapperFactory
{
	public static AuthenticationResultAdapter create()
	{
		return new DefaultAuthenticationResultAdapter();
	}

	private AuthenticationResultMapperFactory()
	{
	}
}