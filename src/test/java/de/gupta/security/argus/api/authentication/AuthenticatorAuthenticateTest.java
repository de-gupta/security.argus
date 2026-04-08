package de.gupta.security.argus.api.authentication;

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

	private static AuthenticatorConfiguration<String, String> baseConfiguration(
			final IdentityMappingConfiguration<String, String> identityMappingConfiguration)
	{
		return baseConfiguration(identityMappingConfiguration,
				AuthenticatedTokenVerificationConfiguration.of(TokenTrustPolicy.of(Duration.ZERO,
						true,
						Set.of(AUDIENCE),
						Optional.of(INTERNAL_ISSUER))));
	}

	private static AuthenticatorConfiguration<String, String> baseConfiguration(
			final IdentityMappingConfiguration<String, String> identityMappingConfiguration,
			final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration)
	{
		return AuthenticatorConfiguration.<String, String>builder()
		                                 .upstreamTrustConfiguration(UpstreamTrustConfiguration.Hmac.of(
												 TokenTrustPolicy.of(Duration.ZERO, true, Set.of(AUDIENCE),
														 Optional.of(UPSTREAM_ISSUER)),
												 UPSTREAM_SECRET))
		                                 .authenticatedTokenContract(AuthenticatedTokenContract.of(INTERNAL_ISSUER,
												 Set.of(AUDIENCE),
												 Duration.ofMinutes(15)))
		                                 .authenticatedTokenMintingConfiguration(
												 AuthenticatedTokenMintingConfiguration.of(
														 TokenSignerConfiguration.Hmac.of(INTERNAL_SECRET)))
		                                 .authenticatedTokenVerificationConfiguration(
												 authenticatedTokenVerificationConfiguration)
		                                 .identityMappingConfiguration(identityMappingConfiguration)
		                                 .clock(CLOCK)
		                                 .build();
	}

	private static String upstreamToken(final String subject, final Map<String, Object> claims)
	{
		return signedUpstreamToken(subject, claims, UPSTREAM_SECRET);
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

	private record SuccessCase(String description, Authenticator authenticator, String token)
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
		}

		private Stream<Arguments> cases()
		{
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					IdentityMappingConfiguration.of(externalIdentity -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER", "ROLE_ADMIN"),
							_ -> 7L)));

			return Stream.of(new SuccessCase("when upstream token resolves and stays current",
								 authenticator,
								 upstreamToken("external-123", Map.of())))
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
					IdentityMappingConfiguration.of(externalIdentity -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
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
					IdentityMappingConfiguration.of("email",
							externalIdentity -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L)));
			final Authenticator missingUserAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					IdentityMappingConfiguration.of(externalIdentity -> Optional.<String>empty(),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L)));
			final Authenticator missingSubjectAuthenticator = AuthenticatorFactory.create(baseConfiguration(
					IdentityMappingConfiguration.of(externalIdentity -> Optional.of("user-123"),
							_ -> " ",
							_ -> Set.of("ROLE_USER"),
							_ -> 7L)));

			return Stream.of(
								 new IdentityFailureCase("when configured external identity claim is missing",
										 missingIdentityAuthenticator,
										 upstreamToken("external-123", Map.of()),
										 IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY),
								 new IdentityFailureCase("when no local user can be resolved",
										 missingUserAuthenticator,
										 upstreamToken("external-123", Map.of()),
										 IdentityNotResolvedReason.USER_NOT_FOUND),
								 new IdentityFailureCase("when no stable local subject can be resolved",
										 missingSubjectAuthenticator,
										 upstreamToken("external-123", Map.of()),
										 IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT))
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
			final AtomicLong version = new AtomicLong(7L);
			final Authenticator authenticator = AuthenticatorFactory.create(baseConfiguration(
					IdentityMappingConfiguration.of(externalIdentity -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> version.getAndIncrement())));

			return Stream.of(new FailureCase("when token version is outdated immediately after minting",
								 authenticator,
								 upstreamToken("external-123", Map.of())))
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
					IdentityMappingConfiguration.of(externalIdentity -> Optional.of("user-123"),
							user -> "local-" + user,
							_ -> Set.of("ROLE_USER"),
							_ -> 7L),
					AuthenticatedTokenVerificationConfiguration.of(
							TokenTrustPolicy.of(Duration.ZERO, true, Set.of(AUDIENCE), Optional.of("wrong-issuer")))));

			return Stream.of(new FailureCase("when internally issued token cannot be re-verified",
								 authenticator,
								 upstreamToken("external-123", Map.of())))
			             .map(Arguments::of);
		}
	}
}