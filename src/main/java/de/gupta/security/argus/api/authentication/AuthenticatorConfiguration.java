package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;

import java.time.Clock;
import java.util.Objects;

public record AuthenticatorConfiguration<User>(UpstreamTrustConfiguration upstreamTrustConfiguration,
                                               AuthenticatedTokenConfiguration authenticatedTokenConfiguration,
                                               IdentityMappingConfiguration<User> identityMappingConfiguration,
                                               Clock clock)
{
	public static <User> AuthenticatorConfiguration<User> of(
			final UpstreamTrustConfiguration upstreamTrustConfiguration,
			final AuthenticatedTokenConfiguration authenticatedTokenConfiguration,
			final IdentityMappingConfiguration<User> identityMappingConfiguration,
			final Clock clock)
	{
		return new AuthenticatorConfiguration<>(upstreamTrustConfiguration,
				authenticatedTokenConfiguration,
				identityMappingConfiguration,
				clock);
	}

	public static <User> AuthenticatorConfiguration<User> of(
			final UpstreamTrustConfiguration upstreamTrustConfiguration,
			final AuthenticatedTokenConfiguration authenticatedTokenConfiguration,
			final IdentityMappingConfiguration<User> identityMappingConfiguration)
	{
		return of(upstreamTrustConfiguration,
				authenticatedTokenConfiguration,
				identityMappingConfiguration,
				Clock.systemUTC());
	}

	public AuthenticatorConfiguration
	{
		upstreamTrustConfiguration =
				Objects.requireNonNull(upstreamTrustConfiguration, "upstreamTrustConfiguration must not be null");
		authenticatedTokenConfiguration = Objects.requireNonNull(authenticatedTokenConfiguration,
				"authenticatedTokenConfiguration must not be null");
		identityMappingConfiguration = Objects.requireNonNull(identityMappingConfiguration,
				"identityMappingConfiguration must not be null");
		clock = Objects.requireNonNull(clock, "clock must not be null");
	}
}
