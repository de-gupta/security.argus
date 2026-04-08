package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

final class AuthenticatorConfigurationTest
{
	@Test
	void shouldCreateWithSplitAuthenticatedTokenSettings()
	{
		final UpstreamTrustConfiguration upstreamTrustConfiguration =
				UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO), "upstream-secret");
		final AuthenticatedTokenContract authenticatedTokenContract =
				AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15));
		final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration =
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of("minting-secret"));
		final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration =
				AuthenticatedTokenVerificationConfiguration.of(
						TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), Optional.of("argus")));
		final IdentityMappingConfiguration<String> identityMappingConfiguration =
				IdentityMappingConfiguration.of(externalId -> Optional.of("local-" + externalId),
						user -> user,
						_ -> Set.of("ROLE_USER"),
						_ -> 7L);
		final Clock clock = Clock.systemUTC();

		final AuthenticatorConfiguration<String> configuration = AuthenticatorConfiguration.of(
				upstreamTrustConfiguration,
				authenticatedTokenContract,
				authenticatedTokenMintingConfiguration,
				authenticatedTokenVerificationConfiguration,
				identityMappingConfiguration,
				clock);

		assertThat(configuration.upstreamTrustConfiguration()).isEqualTo(upstreamTrustConfiguration);
		assertThat(configuration.authenticatedTokenContract()).isEqualTo(authenticatedTokenContract);
		assertThat(configuration.authenticatedTokenMintingConfiguration())
				.isEqualTo(authenticatedTokenMintingConfiguration);
		assertThat(configuration.authenticatedTokenVerificationConfiguration())
				.isEqualTo(authenticatedTokenVerificationConfiguration);
		assertThat(configuration.identityMappingConfiguration()).isEqualTo(identityMappingConfiguration);
		assertThat(configuration.clock()).isEqualTo(clock);
	}

	@Test
	void shouldDefaultClockToSystemUtc()
	{
		final AuthenticatorConfiguration<String> configuration = AuthenticatorConfiguration.of(
				UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO), "upstream-secret"),
				AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15)),
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of("minting-secret")),
				AuthenticatedTokenVerificationConfiguration.of(
						TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), Optional.of("argus"))),
				IdentityMappingConfiguration.of(externalId -> Optional.of(externalId),
						user -> user,
						_ -> Set.of("ROLE_USER"),
						_ -> 1L));

		assertThat(configuration.clock().getZone()).isEqualTo(ZoneOffset.UTC);
	}
}