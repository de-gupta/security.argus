package de.gupta.security.argus.api;

import java.time.Clock;
import java.util.Objects;

// TODO: this is a huge ugly class and not very ergonomic. break these into smaller pieces and it needs to be way
//  friendlier
public record AuthenticationConfiguration<User>(UpstreamTokenTrustConfiguration upstreamTokenTrustConfiguration,
                                                InternalTokenCryptographyConfiguration internalTokenCryptographyConfiguration,
                                                InternalTokenPolicy internalTokenPolicy,
                                                String externalIdentityClaimName,
                                                UserResolver<String, User> userResolver,
                                                LocalSubjectResolver<User> localSubjectResolver,
                                                RoleResolver<User> roleResolver,
                                                TokenVersionResolver<User> tokenVersionResolver,
                                                CustomClaimEnricher<User> customClaimEnricher,
                                                Clock clock)
{
	public static <User> AuthenticationConfiguration<User> of(
			final UpstreamTokenTrustConfiguration upstreamTokenTrustConfiguration,
			final InternalTokenCryptographyConfiguration internalTokenCryptographyConfiguration,
			final InternalTokenPolicy internalTokenPolicy,
			final String externalIdentityClaimName,
			final UserResolver<String, User> userResolver,
			final LocalSubjectResolver<User> localSubjectResolver,
			final RoleResolver<User> roleResolver,
			final TokenVersionResolver<User> tokenVersionResolver,
			final CustomClaimEnricher<User> customClaimEnricher,
			final Clock clock)
	{
		return new AuthenticationConfiguration<>(upstreamTokenTrustConfiguration,
				internalTokenCryptographyConfiguration,
				internalTokenPolicy,
				externalIdentityClaimName,
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				customClaimEnricher,
				clock);
	}

	public static <User> AuthenticationConfiguration<User> of(
			final UpstreamTokenTrustConfiguration upstreamTokenTrustConfiguration,
			final InternalTokenCryptographyConfiguration internalTokenCryptographyConfiguration,
			final InternalTokenPolicy internalTokenPolicy,
			final UserResolver<String, User> userResolver,
			final LocalSubjectResolver<User> localSubjectResolver,
			final RoleResolver<User> roleResolver,
			final TokenVersionResolver<User> tokenVersionResolver)
	{
		return of(upstreamTokenTrustConfiguration,
				internalTokenCryptographyConfiguration,
				internalTokenPolicy,
				"sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				CustomClaimEnricher.none(),
				Clock.systemUTC());
	}

	public AuthenticationConfiguration
	{
		upstreamTokenTrustConfiguration =
				Objects.requireNonNull(upstreamTokenTrustConfiguration,
						"upstreamTokenTrustConfiguration must not be null");
		internalTokenCryptographyConfiguration =
				Objects.requireNonNull(internalTokenCryptographyConfiguration,
						"internalTokenCryptographyConfiguration must not be null");
		internalTokenPolicy = Objects.requireNonNull(internalTokenPolicy, "internalTokenPolicy must not be null");
		externalIdentityClaimName = requireNonBlank(externalIdentityClaimName,
				"externalIdentityClaimName must not be blank");
		userResolver = Objects.requireNonNull(userResolver, "userResolver must not be null");
		localSubjectResolver = Objects.requireNonNull(localSubjectResolver, "localSubjectResolver must not be null");
		roleResolver = Objects.requireNonNull(roleResolver, "roleResolver must not be null");
		tokenVersionResolver = Objects.requireNonNull(tokenVersionResolver, "tokenVersionResolver must not be null");
		customClaimEnricher = Objects.requireNonNull(customClaimEnricher, "customClaimEnricher must not be null");
		clock = Objects.requireNonNull(clock, "clock must not be null");
	}

	private static String requireNonBlank(final String value, final String message)
	{
		if (value == null || value.isBlank())
		{
			throw new IllegalArgumentException(message);
		}
		return value;
	}
}