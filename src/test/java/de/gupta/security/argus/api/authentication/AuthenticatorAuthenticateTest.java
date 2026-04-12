package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
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

	// Token iat = CLOCK.instant(). NEVER_REVOKED means lastRevokedAt = EPOCH → always current.
	// REVOKED_AFTER_ISSUANCE means lastRevokedAt > token.iat → token is stale.
	private static final Instant NEVER_REVOKED = Instant.EPOCH;
	private static final Instant REVOKED_AFTER_ISSUANCE = CLOCK.instant().plusSeconds(1);

	private static <ExternalIdentity> AuthenticatorConfiguration<ExternalIdentity, String> baseConfiguration(
			final CryptoMaterial cryptoMaterial,
			final IdentityMappingConfiguration<ExternalIdentity, String> identityMappingConfiguration)
	{
		return AuthenticatorConfiguration.<ExternalIdentity, String>builder()
		                                 .upstreamTrustConfiguration(cryptoMaterial.upstreamTrustConfiguration())
		                                 .authenticatedTokenContract(AuthenticatedTokenContract.of(INTERNAL_ISSUER,
												 Set.of(AUDIENCE),
												 Duration.ofMinutes(15)))
		                                 .authenticatedTokenMintingConfiguration(
												 cryptoMaterial.authenticatedTokenMintingConfiguration())
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

	@FunctionalInterface
	private interface UpstreamTokenFactory
	{
		String create(String subject, Map<String, Object> claims);
	}

	private record ExternalIdentity(String value)
	{
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
		void shouldReturnAuthenticatedIdentity(final String description, final Authenticator authenticator,
		                                       final String token)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			assertThat(result).as(description).isInstanceOf(AuthenticationSuccess.class);
			final AuthenticationSuccess success = (AuthenticationSuccess) result;
			assertThat(success.identity().subject()).as(description).isEqualTo("local-user-123");
			assertThat(success.identity().issuer()).as(description).contains(INTERNAL_ISSUER);
			assertThat(success.identity().audiences()).as(description).containsExactly(AUDIENCE);
			assertThat(success.identity().roles()).as(description).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
			assertThat(success.identity().issuedAt()).as(description).contains(CLOCK.instant());
			assertThat(success.identity().expiresAt()).as(description)
			                                          .contains(CLOCK.instant().plus(Duration.ofMinutes(15)));
			assertThat(success.identity().notBefore()).as(description).isEmpty();
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(hmacMaterial(), rsaMaterial(), ecMaterial())
			             .map(cryptoMaterial -> Arguments.of(
								 "when " + cryptoMaterial.description() + " exchange resolves and is current",
								 AuthenticatorFactory.create(baseConfiguration(cryptoMaterial,
										 IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
												 _ -> Optional.of("user-123"),
												 user -> "local-" + user,
												 _ -> Set.of("ROLE_USER", "ROLE_ADMIN"),
												 _ -> NEVER_REVOKED))),
								 cryptoMaterial.upstreamToken("external-123", Map.of())));
		}
	}

	@Nested
	@DisplayName("as invalid upstream credential")
	@TestInstance(PER_CLASS)
	final class InvalidUpstreamCredential
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldRejectInvalidCredential(final String description, final Authenticator authenticator,
		                                   final String token)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			assertThat(result).as(description).isInstanceOf(InvalidCredential.class);
			assertThat(((InvalidCredential) result).reason()).as(description)
			                                                 .isEqualTo(InvalidCredentialReason.INVALID_SIGNATURE);
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> NEVER_REVOKED)));

			return Stream.of(Arguments.of("when upstream signature does not match",
					authenticator,
					signedUpstreamToken("external-123", Map.of(), DIFFERENT_UPSTREAM_SECRET)));
		}
	}

	@Nested
	@DisplayName("as identity resolution failure")
	@TestInstance(PER_CLASS)
	final class IdentityResolutionFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnIdentityFailure(final String description, final Authenticator authenticator,
		                                 final String token, final IdentityNotResolvedReason expectedReason)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			assertThat(result).as(description).isInstanceOf(IdentityNotResolved.class);
			assertThat(((IdentityNotResolved) result).reason()).as(description).isEqualTo(expectedReason);
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
							_ -> NEVER_REVOKED)));
			final Authenticator missingUserAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.empty(),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> NEVER_REVOKED)));
			final Authenticator missingSubjectAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							_ -> " ",
							_ -> Set.of("ROLE_USER"),
							_ -> NEVER_REVOKED)));

			return Stream.of(
					Arguments.of("when configured external identity claim is missing",
							missingIdentityAuthenticator,
							hmacMaterial().upstreamToken("external-123", Map.of()),
							IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY),
					Arguments.of("when no local user can be resolved",
							missingUserAuthenticator,
							hmacMaterial().upstreamToken("external-123", Map.of()),
							IdentityNotResolvedReason.USER_NOT_FOUND),
					Arguments.of("when no stable local subject can be resolved",
							missingSubjectAuthenticator,
							hmacMaterial().upstreamToken("external-123", Map.of()),
							IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT));
		}
	}

	@Nested
	@DisplayName("as adapted external identity")
	@TestInstance(PER_CLASS)
	final class AdaptedExternalIdentity
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldAdaptExternalIdentityBeforeResolvingUser(final String description,
		                                                    final Authenticator authenticator, final String token)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			assertThat(result).as(description).isInstanceOf(AuthenticationSuccess.class);
			assertThat(((AuthenticationSuccess) result).identity().subject()).as(description)
			                                                                 .isEqualTo("local-user-123");
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(hmacMaterial(),
					IdentityMappingConfiguration.of(rawIdentity -> Optional.of(new ExternalIdentity(rawIdentity)),
							externalIdentity -> Optional.of(externalIdentity.value().replace("external", "user")),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> NEVER_REVOKED)));

			return Stream.of(Arguments.of("when an adapter transforms the raw external identity",
					authenticator,
					hmacMaterial().upstreamToken("external-123", Map.of())));
		}
	}

	@Nested
	@DisplayName("as currentness failure (token superseded by revocation)")
	@TestInstance(PER_CLASS)
	final class CurrentnessFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnNotCurrent(final String description, final Authenticator authenticator, final String token)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			assertThat(result).as(description).isInstanceOf(AuthenticationNotCurrent.class);
			assertThat(((AuthenticationNotCurrent) result).reason()).as(description)
			                                                        .isEqualTo(AuthenticationNotCurrentReason.REVOKED);
		}

		private Stream<Arguments> cases()
		{
			// Token iat = CLOCK.instant(). lastRevokedAt = CLOCK.instant().plusSeconds(1) > iat → superseded.
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> REVOKED_AFTER_ISSUANCE)));

			return Stream.of(Arguments.of("when token was issued before the last revocation event",
					authenticator,
					hmacMaterial().upstreamToken("external-123", Map.of())));
		}
	}

	@Nested
	@DisplayName("as revocation state unavailable")
	@TestInstance(PER_CLASS)
	final class RevocationStateUnavailable
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnUnavailableWhenRevocationResolutionThrows(final String description,
		                                                           final Authenticator authenticator,
		                                                           final String token)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			assertThat(result).as(description).isInstanceOf(AuthenticationUnavailable.class);
			assertThat(((AuthenticationUnavailable) result).reason()).as(description)
			                                                         .isEqualTo(
																			 AuthenticationUnavailableReason.IDENTITY_STATE_UNAVAILABLE);
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ ->
							{
								throw new RuntimeException("revocation store offline");
							})));

			return Stream.of(Arguments.of("when revocation store throws during currentness check",
					authenticator,
					hmacMaterial().upstreamToken("external-123", Map.of())));
		}
	}

	@Nested
	@DisplayName("as runtime pipeline failure during revocation check")
	@TestInstance(PER_CLASS)
	final class RuntimePipelineFailure
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldReturnUnavailableWhenResolutionThrows(final String description, final Authenticator authenticator,
		                                                 final String token)
		{
			final AuthenticationResult result = authenticator.authenticate(token);

			// User resolver throws during augustus revocation check (before hermes exchange),
			// which maps to IDENTITY_STATE_UNAVAILABLE (revocation state unavailable).
			assertThat(result).as(description).isInstanceOf(AuthenticationUnavailable.class);
			assertThat(((AuthenticationUnavailable) result).reason()).as(description)
			                                                         .isEqualTo(
																			 AuthenticationUnavailableReason.IDENTITY_STATE_UNAVAILABLE);
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(hmacMaterial(),
					IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
							_ ->
							{
								throw new IllegalStateException("user lookup offline");
							},
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> NEVER_REVOKED)));

			return Stream.of(Arguments.of("when user resolution throws during revocation check",
					authenticator,
					hmacMaterial().upstreamToken("external-123", Map.of())));
		}
	}
}