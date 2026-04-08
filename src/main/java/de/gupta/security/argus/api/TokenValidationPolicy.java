package de.gupta.security.argus.api;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record TokenValidationPolicy(Duration clockSkew,
                                    boolean requireSubject,
                                    Set<String> expectedAudiences,
                                    Optional<String> expectedIssuer)
{
	public static TokenValidationPolicy of(final Duration clockSkew,
	                                       final boolean requireSubject,
	                                       final Set<String> expectedAudiences,
	                                       final Optional<String> expectedIssuer)
	{
		return new TokenValidationPolicy(clockSkew, requireSubject, expectedAudiences, expectedIssuer);
	}

	public static TokenValidationPolicy of(final Duration clockSkew,
	                                       final boolean requireSubject,
	                                       final Set<String> expectedAudiences)
	{
		return of(clockSkew, requireSubject, expectedAudiences, Optional.empty());
	}

	public static TokenValidationPolicy of(final Duration clockSkew, final boolean requireSubject)
	{
		return of(clockSkew, requireSubject, Set.of(), Optional.empty());
	}

	public static TokenValidationPolicy of(final Duration clockSkew)
	{
		return of(clockSkew, false, Set.of(), Optional.empty());
	}

	public static TokenValidationPolicy create()
	{
		return of(Duration.ZERO);
	}

	public TokenValidationPolicy
	{
		clockSkew = Objects.requireNonNull(clockSkew, "clockSkew must not be null");
		if (clockSkew.isNegative())
		{
			throw new IllegalArgumentException("clockSkew must not be negative");
		}
		expectedAudiences = Set.copyOf(Objects.requireNonNull(expectedAudiences, "expectedAudiences must not be null"));
		expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer must not be null")
		                        .map(value -> requireNonBlank(value, "expectedIssuer must not be blank"));
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
