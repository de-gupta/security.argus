package de.gupta.security.argus.api.token;

import de.gupta.security.argus.api.trust.TokenTrustPolicy;

import java.util.Objects;

public record AuthenticatedTokenConfiguration(TokenSignerConfiguration tokenSignerConfiguration,
                                              AuthenticatedTokenContract authenticatedTokenContract,
                                              TokenTrustPolicy trustPolicy)
{
	public static AuthenticatedTokenConfiguration of(final TokenSignerConfiguration tokenSignerConfiguration,
	                                                 final AuthenticatedTokenContract authenticatedTokenContract,
	                                                 final TokenTrustPolicy trustPolicy)
	{
		return new AuthenticatedTokenConfiguration(tokenSignerConfiguration, authenticatedTokenContract, trustPolicy);
	}
}