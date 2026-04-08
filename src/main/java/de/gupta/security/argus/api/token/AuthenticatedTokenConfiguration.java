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

	public AuthenticatedTokenConfiguration
	{
		tokenSignerConfiguration = Objects.requireNonNull(tokenSignerConfiguration,
				"tokenSignerConfiguration must not be null");
		authenticatedTokenContract = Objects.requireNonNull(authenticatedTokenContract,
				"authenticatedTokenContract must not be null");
		trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy must not be null");
	}
}
