package de.gupta.security.argus.support;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
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
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class TestAuthenticationResults
{
	private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-04-09T12:00:00Z"), ZoneOffset.UTC);
	private static final String UPSTREAM_ISSUER = "supabase";
	private static final String INTERNAL_ISSUER = "argus";
	private static final String AUDIENCE = "inventory";
	private static final String UPSTREAM_SECRET = "upstream-secret-value-that-is-long-enough";
	private static final String INTERNAL_SECRET = "internal-secret-value-that-is-long-enough";

	public static AuthenticationSuccess success(final String subject)
	{
		final Authenticator authenticator = AuthenticatorFactory.create(
				AuthenticatorConfiguration.of(
						UpstreamTrustConfiguration.Hmac.of(
								TokenTrustPolicy.of(Duration.ZERO,
										true,
										Set.of(AUDIENCE),
										Optional.of(UPSTREAM_ISSUER)),
								UPSTREAM_SECRET),
						AuthenticatedTokenContract.of(INTERNAL_ISSUER, Set.of(AUDIENCE), Duration.ofMinutes(15)),
						AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of(INTERNAL_SECRET)),
						AuthenticatedTokenVerificationConfiguration.of(
								TokenTrustPolicy.of(Duration.ZERO,
										true,
										Set.of(AUDIENCE),
										Optional.of(INTERNAL_ISSUER))),
						IdentityMappingConfiguration.of(
								ExternalIdentityAdapter.stringIdentity(),
								_ -> Optional.of("user-123"),
								_ -> subject,
								_ -> Set.of("ROLE_USER"),
								_ -> 7L,
								_ -> 7L),
						CLOCK));

		final AuthenticationResult result = authenticator.authenticate(signedUpstreamToken("external-123"));
		return (AuthenticationSuccess) result;
	}

	private static String signedUpstreamToken(final String subject)
	{
		final var builder = Jwts.builder()
		                        .subject(subject)
		                        .issuer(UPSTREAM_ISSUER)
		                        .issuedAt(Date.from(CLOCK.instant()))
		                        .expiration(Date.from(CLOCK.instant().plus(Duration.ofMinutes(30))))
		                        .claims(Map.of())
		                        .signWith(Keys.hmacShaKeyFor(UPSTREAM_SECRET.getBytes(StandardCharsets.UTF_8)));
		builder.audience().add(Set.of(AUDIENCE)).and();
		return builder.compact();
	}

	private TestAuthenticationResults()
	{
	}
}
