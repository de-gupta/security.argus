package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("LazyAuthenticationDependencies")
@TestInstance(PER_CLASS)
final class LazyAuthenticationDependenciesTest
{
	private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-04-09T12:00:00Z"), ZoneOffset.UTC);

	private static AuthenticatorConfiguration<String, String> hmacConfiguration()
	{
		return AuthenticatorConfiguration.of(
				UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO,
								true,
								Set.of("inventory"),
								Optional.of("supabase")),
						"upstream-secret-value-that-is-long-enough"),
				AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15)),
				AuthenticatedTokenMintingConfiguration.of(
						TokenSignerConfiguration.Hmac.of("internal-secret-value-that-is-long-enough")),
				AuthenticatedTokenVerificationConfiguration.of(
						TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), Optional.of("argus"))),
				identityMappingConfiguration(),
				CLOCK);
	}

	private static AuthenticatorConfiguration<String, String> rsaConfiguration()
	{
		final KeyPair keyPair = generateKeyPair("RSA", 2048);
		final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		return AuthenticatorConfiguration.of(
				UpstreamTrustConfiguration.Rsa.of(TokenTrustPolicy.of(Duration.ZERO,
								true,
								Set.of("inventory"),
								Optional.of("supabase")),
						publicKey),
				AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15)),
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Rsa.of(privateKey, publicKey)),
				AuthenticatedTokenVerificationConfiguration.of(
						TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), Optional.of("argus"))),
				identityMappingConfiguration(),
				CLOCK);
	}

	private static AuthenticatorConfiguration<String, String> ecConfiguration()
	{
		final KeyPair keyPair = generateKeyPair("EC", 256);
		final ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		final ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		return AuthenticatorConfiguration.of(
				UpstreamTrustConfiguration.Ec.of(TokenTrustPolicy.of(Duration.ZERO,
								true,
								Set.of("inventory"),
								Optional.of("supabase")),
						publicKey),
				AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15)),
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Ec.of(privateKey, publicKey)),
				AuthenticatedTokenVerificationConfiguration.of(
						TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), Optional.of("argus"))),
				identityMappingConfiguration(),
				CLOCK);
	}

	private static IdentityMappingConfiguration<String, String> identityMappingConfiguration()
	{
		return IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
				externalIdentity -> Optional.of("user-123"),
				user -> "local-" + user,
				_ -> Set.of("ROLE_USER"),
				_ -> 7L,
				_ -> 7L);
	}

	private static KeyPair generateKeyPair(final String algorithm, final int keySize)
	{
		try
		{
			final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
			generator.initialize(keySize);
			return generator.generateKeyPair();
		}
		catch (NoSuchAlgorithmException exception)
		{
			throw new IllegalStateException(exception);
		}
	}

	private record DependencyCase(String description, AuthenticatorConfiguration<String, String> configuration)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	@Nested
	@DisplayName("as dependency creation")
	@TestInstance(PER_CLASS)
	final class DependencyCreation
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldCreateDependenciesAcrossAlgorithms(final DependencyCase input)
		{
			final LazyAuthenticationDependencies<String, String> dependencies =
					LazyAuthenticationDependencies.create(input.configuration());

			final AuthenticationDependencies first = dependencies.summon();
			final AuthenticationDependencies second = dependencies.summon();

			assertThat(first)
					.as(input.description())
					.isSameAs(second);
			assertThat(first.tokenExchangeService())
					.as(input.description())
					.isNotNull();
			assertThat(first.authenticatedTokenVerifier())
					.as(input.description())
					.isNotNull();
			assertThat(first.tokenVersionVerifier())
					.as(input.description())
					.isNotNull();
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(
								 new DependencyCase("when HMAC dependencies are created lazily", hmacConfiguration()),
								 new DependencyCase("when RSA dependencies are created lazily", rsaConfiguration()),
								 new DependencyCase("when EC dependencies are created lazily", ecConfiguration()))
			             .map(Arguments::of);
		}
	}
}