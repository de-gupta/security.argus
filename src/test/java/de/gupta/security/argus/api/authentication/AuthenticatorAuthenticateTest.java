package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailableReason;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolvedReason;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.security.Key;
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
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("Authenticator.authenticate")
@TestInstance(PER_CLASS)
final class AuthenticatorAuthenticateTest
{
	private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-04-09T12:00:00Z"), ZoneOffset.UTC);
	private static final String UPSTREAM_ISSUER = "supabase";
	private static final String INTERNAL_ISSUER = "argus";
	private static final String AUDIENCE = "inventory";
	private static final String UPSTREAM_SECRET = "upstream-secret-value-that-is-long-enough";
	private static final String DIFFERENT_UPSTREAM_SECRET = "other-upstream-secret-value-long-enough";
	private static final String INTERNAL_SECRET = "internal-secret-value-that-is-long-enough";

	private static <ExternalIdentity> AuthenticatorConfiguration<ExternalIdentity, String> baseConfiguration(
			final CryptoMaterial cryptoMaterial,
			final IdentityMappingConfiguration<ExternalIdentity, String> identityMappingConfiguration)
	{
		return baseConfiguration(cryptoMaterial,
				identityMappingConfiguration,
				AuthenticatedTokenVerificationConfiguration.of(TokenTrustPolicy.of(Duration.ZERO,
						true,
						Set.of(AUDIENCE),
						Optional.of(INTERNAL_ISSUER))));
	}

	private static <ExternalIdentity> AuthenticatorConfiguration<ExternalIdentity, String> baseConfiguration(
			final CryptoMaterial cryptoMaterial,
			final IdentityMappingConfiguration<ExternalIdentity, String> identityMappingConfiguration,
			final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration)
	{
		return AuthenticatorConfiguration.<ExternalIdentity, String>builder()
		                                 .upstreamTrustConfiguration(cryptoMaterial.upstreamTrustConfiguration())
		                                 .authenticatedTokenContract(AuthenticatedTokenContract.of(INTERNAL_ISSUER,
												 Set.of(AUDIENCE),
												 Duration.ofMinutes(15)))
		                                 .authenticatedTokenMintingConfiguration(
												 cryptoMaterial.authenticatedTokenMintingConfiguration())
		                                 .authenticatedTokenVerificationConfiguration(
												 authenticatedTokenVerificationConfiguration)
		                                 .identityMappingConfiguration(identityMappingConfiguration)
		                                 .clock(CLOCK)
		                                 .build();
	}

	private static String signedUpstreamToken(final String subject,
	                                          final Map<String, Object> claims,
	                                          final String secret)
	{
		final var builder = Jwts.builder()
		                        .subject(subject)
		                        .issuer(UPSTREAM_ISSUER)
		                        .issuedAt(Date.from(CLOCK.instant()))
		                        .expiration(Date.from(CLOCK.instant().plus(Duration.ofMinutes(30))))
		                        .claims(claims)
		                        .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)));
		builder.audience().add(Set.of(AUDIENCE)).and();
		return builder.compact();
	}

	private static String signedUpstreamToken(final String subject,
	                                          final Map<String, Object> claims,
	                                          final String issuer,
	                                          final Key signingKey)
	{
		final var builder = Jwts.builder()
		                        .subject(subject)
		                        .issuer(issuer)
		                        .issuedAt(Date.from(CLOCK.instant()))
		                        .expiration(Date.from(CLOCK.instant().plus(Duration.ofMinutes(30))))
		                        .claims(claims)
		                        .signWith(signingKey);
		builder.audience().add(Set.of(AUDIENCE)).and();
		return builder.compact();
	}

	private static CryptoMaterial hmacMaterial()
	{
		return new CryptoMaterial("HMAC",
				UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO,
								true,
								Set.of(AUDIENCE),
								Optional.of(UPSTREAM_ISSUER)),
						UPSTREAM_SECRET),
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of(INTERNAL_SECRET)),
				(subject, claims) -> signedUpstreamToken(subject, claims, UPSTREAM_SECRET));
	}

	private static CryptoMaterial rsaMaterial()
	{
		final KeyPair keyPair = generateKeyPair("RSA", 2048);
		final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		return new CryptoMaterial("RSA",
				UpstreamTrustConfiguration.Rsa.of(TokenTrustPolicy.of(Duration.ZERO,
								true,
								Set.of(AUDIENCE),
								Optional.of(UPSTREAM_ISSUER)),
						publicKey),
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Rsa.of(privateKey, publicKey)),
				(subject, claims) -> signedUpstreamToken(subject, claims, UPSTREAM_ISSUER, privateKey));
	}

	private static CryptoMaterial ecMaterial()
	{
		final KeyPair keyPair = generateKeyPair("EC", 256);
		final ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		final ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		return new CryptoMaterial("EC",
				UpstreamTrustConfiguration.Ec.of(TokenTrustPolicy.of(Duration.ZERO,
								true,
								Set.of(AUDIENCE),
								Optional.of(UPSTREAM_ISSUER)),
						publicKey),
				AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Ec.of(privateKey, publicKey)),
				(subject, claims) -> signedUpstreamToken(subject, claims, UPSTREAM_ISSUER, privateKey));
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

	private record SuccessCase(String description, Authenticator authenticator, String token)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record AdaptedSuccessCase(String description, Authenticator authenticator, String token)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record FailureCase(String description, Authenticator authenticator, String token)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record IdentityFailureCase(String description,
	                                   Authenticator authenticator,
	                                   String token,
	                                   IdentityNotResolvedReason expectedReason)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	@FunctionalInterface
	private interface UpstreamTokenFactory
	{
		String create(String subject, Map<String, Object> claims);
	}

	private record ExternalIdentity(String value)
	{
	}

	private record RuntimeFailureCase(String description, Authenticator authenticator, String token)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record CryptoMaterial(String description,
	                              UpstreamTrustConfiguration upstreamTrustConfiguration,
	                              AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
	                              UpstreamTokenFactory upstreamTokenFactory)
	{
		String upstreamToken(final String subject, final Map<String, Object> claims)
		{
			return upstreamTokenFactory.create(subject, claims);
		}
	}

	@Nested
	@DisplayName("as successful authentication")
	@TestInstance(PER_CLASS)
	final class SuccessfulAuthentication
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnAuthenticatedIdentity(final SuccessCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(AuthenticationSuccess.class);

			final AuthenticationSuccess success = (AuthenticationSuccess) result;
			assertThat(success.identity().subject())
					.as(input.description())
					.isEqualTo("local-user-123");
			assertThat(success.identity().issuer())
					.as(input.description())
					.contains(INTERNAL_ISSUER);
			assertThat(success.identity().audiences())
					.as(input.description())
					.containsExactly(AUDIENCE);
			assertThat(success.identity().roles())
					.as(input.description())
					.containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
			assertThat(success.identity().issuedAt())
					.as(input.description())
					.contains(CLOCK.instant());
			assertThat(success.identity().expiresAt())
					.as(input.description())
					.contains(CLOCK.instant().plus(Duration.ofMinutes(15)));
			assertThat(success.identity().notBefore())
					.as(input.description())
					.isEmpty();
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(hmacMaterial(), rsaMaterial(), ecMaterial())
			             .map(cryptoMaterial -> new SuccessCase(
								 "when " + cryptoMaterial.description() + " exchange resolves and stays current",
								 AuthenticatorFactory.create(baseConfiguration(
										 cryptoMaterial,
										 IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
												 _ -> Optional.of("user-123"),
												 user -> "local-" + user,
												 _ -> Set.of("ROLE_USER", "ROLE_ADMIN"),
												 _ -> 7L,
												 _ -> 7L))),
								 cryptoMaterial.upstreamToken("external-123", Map.of())))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as invalid upstream credential")
	@TestInstance(PER_CLASS)
	final class InvalidUpstreamCredential
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldRejectInvalidCredential(final FailureCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(InvalidCredential.class);
			assertThat(((InvalidCredential) result).reason())
					.as(input.description())
					.isEqualTo(InvalidCredentialReason.INVALID_SIGNATURE);
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L)));

			return Stream.of(new FailureCase("when upstream signature does not match",
								 authenticator,
								 signedUpstreamToken("external-123",
										 Map.of(),
										 DIFFERENT_UPSTREAM_SECRET)))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as identity resolution failure")
	@TestInstance(PER_CLASS)
	final class IdentityResolutionFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnIdentityFailure(final IdentityFailureCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(IdentityNotResolved.class);
			assertThat(((IdentityNotResolved) result).reason())
					.as(input.description())
					.isEqualTo(input.expectedReason());
		}

		private Stream<Arguments> cases()
		{
			final Authenticator missingIdentityAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of("email",
							ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L)));
			final Authenticator missingUserAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.empty(),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L)));
			final Authenticator missingSubjectAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							_ -> " ",
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L)));

			return Stream.of(
								 new IdentityFailureCase("when configured external identity claim is missing",
										 missingIdentityAuthenticator,
										 hmacMaterial().upstreamToken("external-123", Map.of()),
										 IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY),
								 new IdentityFailureCase("when no local user can be resolved",
										 missingUserAuthenticator,
										 hmacMaterial().upstreamToken("external-123", Map.of()),
										 IdentityNotResolvedReason.USER_NOT_FOUND),
								 new IdentityFailureCase("when no stable local subject can be resolved",
										 missingSubjectAuthenticator,
										 hmacMaterial().upstreamToken("external-123", Map.of()),
										 IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as adapted external identity")
	@TestInstance(PER_CLASS)
	final class AdaptedExternalIdentity
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldAdaptExternalIdentityBeforeResolvingUser(final AdaptedSuccessCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(AuthenticationSuccess.class);
			assertThat(((AuthenticationSuccess) result).identity().subject())
					.as(input.description())
					.isEqualTo("local-user-123");
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(rawIdentity -> Optional.of(new ExternalIdentity(rawIdentity)),
							externalIdentity -> Optional.of(externalIdentity.value().replace("external", "user")),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L)));

			return Stream.of(new AdaptedSuccessCase("when an adapter transforms the raw external identity",
								 authenticator,
								 hmacMaterial().upstreamToken("external-123", Map.of())))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as currentness failure")
	@TestInstance(PER_CLASS)
	final class CurrentnessFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnNotCurrent(final FailureCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(AuthenticationNotCurrent.class);
			assertThat(((AuthenticationNotCurrent) result).reason())
					.as(input.description())
					.isEqualTo(AuthenticationNotCurrentReason.VERSION_MISMATCH);
		}

		private Stream<Arguments> cases()
		{
			final AtomicLong currentVersion = new AtomicLong(8L);
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> currentVersion.get())));

			return Stream.of(new FailureCase("when token version is outdated immediately after minting",
								 authenticator,
								 hmacMaterial().upstreamToken("external-123", Map.of())))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as internal pipeline failure")
	@TestInstance(PER_CLASS)
	final class InternalPipelineFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnUnavailable(final FailureCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(AuthenticationUnavailable.class);
			assertThat(((AuthenticationUnavailable) result).reason())
					.as(input.description())
					.isEqualTo(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE);
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L),
					AuthenticatedTokenVerificationConfiguration.of(
							TokenTrustPolicy.of(Duration.ZERO, true, Set.of(AUDIENCE), Optional.of("wrong-issuer")))));

			return Stream.of(new FailureCase("when internally issued token cannot be re-verified",
								 authenticator,
								 hmacMaterial().upstreamToken("external-123", Map.of())))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as runtime pipeline failure")
	@TestInstance(PER_CLASS)
	final class RuntimePipelineFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnUnavailableWhenResolutionThrows(final RuntimeFailureCase input)
		{
			final AuthenticationResult result = input.authenticator().authenticate(input.token());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(AuthenticationUnavailable.class);
			assertThat(((AuthenticationUnavailable) result).reason())
					.as(input.description())
					.isEqualTo(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE);
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ ->
							{
								throw new IllegalStateException("user lookup offline");
							},
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L,
							_ -> 7L)));

			return Stream.of(new RuntimeFailureCase("when user resolution throws unexpectedly",
								 authenticator,
								 hmacMaterial().upstreamToken("external-123", Map.of())))
			             .map(Arguments::of);
		}
	}
}