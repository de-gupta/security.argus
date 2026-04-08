package de.gupta.security.argus.api.token;

import de.gupta.security.argus.api.trust.TokenTrustPolicy;

import java.util.Objects;

public record AuthenticatedTokenVerificationConfiguration(TokenTrustPolicy trustPolicy)
{
	public static AuthenticatedTokenVerificationConfiguration of(final TokenTrustPolicy trustPolicy)
	{
		return new AuthenticatedTokenVerificationConfiguration(trustPolicy);
	}

	public AuthenticatedTokenVerificationConfiguration
	{
		trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy must not be null");
	}
}
