package de.gupta.security.argus.application.service;

public final class AuthenticationResultMapperFactory
{
	public static AuthenticationResultMapper create()
	{
		return new DefaultAuthenticationResultMapper();
	}

	private AuthenticationResultMapperFactory()
	{
	}
}