package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;

import java.time.Clock;
import java.util.Objects;

public record AuthenticatorConfiguration<User>(UpstreamTrustConfiguration upstreamTrustConfiguration,
                                               AuthenticatedTokenContract authenticatedTokenContract,
                                               AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
                                               AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
                                               IdentityMappingConfiguration<User> identityMappingConfiguration,
                                               Clock clock)
{
	public static <User> AuthenticatorConfiguration<User> of(
			final UpstreamTrustConfiguration upstreamTrustConfiguration,
			final AuthenticatedTokenContract authenticatedTokenContract,
			final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
			final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
			final IdentityMappingConfiguration<User> identityMappingConfiguration,
			final Clock clock)
	{
		return new AuthenticatorConfiguration<>(upstreamTrustConfiguration,
				authenticatedTokenContract,
				authenticatedTokenMintingConfiguration,
				authenticatedTokenVerificationConfiguration,
				identityMappingConfiguration,
				clock);
	}

	public static <User> AuthenticatorConfiguration<User> of(
			final UpstreamTrustConfiguration upstreamTrustConfiguration,
			final AuthenticatedTokenContract authenticatedTokenContract,
			final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
			final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
			final IdentityMappingConfiguration<User> identityMappingConfiguration)
	{
		return of(upstreamTrustConfiguration,
				authenticatedTokenContract,
				authenticatedTokenMintingConfiguration,
				authenticatedTokenVerificationConfiguration,
				identityMappingConfiguration,
				Clock.systemUTC());
	}

	public AuthenticatorConfiguration
	{
		upstreamTrustConfiguration =
				Objects.requireNonNull(upstreamTrustConfiguration, "upstreamTrustConfiguration must not be null");
		authenticatedTokenContract = Objects.requireNonNull(authenticatedTokenContract,
				"authenticatedTokenContract must not be null");
		authenticatedTokenMintingConfiguration = Objects.requireNonNull(authenticatedTokenMintingConfiguration,
				"authenticatedTokenMintingConfiguration must not be null");
		authenticatedTokenVerificationConfiguration =
				Objects.requireNonNull(authenticatedTokenVerificationConfiguration,
						"authenticatedTokenVerificationConfiguration must not be null");
		identityMappingConfiguration = Objects.requireNonNull(identityMappingConfiguration,
				"identityMappingConfiguration must not be null");
		clock = Objects.requireNonNull(clock, "clock must not be null");
	}
}
