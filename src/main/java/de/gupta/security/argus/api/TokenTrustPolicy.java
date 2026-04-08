package de.gupta.security.argus.api;

import de.gupta.security.argus.utility.ValidationUtility;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record TokenTrustPolicy(Duration clockSkew,
                               boolean requireSubject,
                               Set<String> expectedAudiences,
                               Optional<String> expectedIssuer)
{
	public static TokenTrustPolicy of(final Duration clockSkew,
	                                  final boolean requireSubject,
	                                  final Set<String> expectedAudiences,
	                                  final Optional<String> expectedIssuer)
	{
		return new TokenTrustPolicy(clockSkew, requireSubject, expectedAudiences, expectedIssuer);
	}

	public static TokenTrustPolicy of(final Duration clockSkew,
	                                  final boolean requireSubject,
	                                  final Set<String> expectedAudiences)
	{
		return of(clockSkew, requireSubject, expectedAudiences, Optional.empty());
	}

	public static TokenTrustPolicy of(final Duration clockSkew, final boolean requireSubject)
	{
		return of(clockSkew, requireSubject, Set.of(), Optional.empty());
	}

	public static TokenTrustPolicy of(final Duration clockSkew)
	{
		return of(clockSkew, false, Set.of(), Optional.empty());
	}

	public static TokenTrustPolicy create()
	{
		return of(Duration.ZERO);
	}

	public TokenTrustPolicy
	{
		clockSkew = Objects.requireNonNull(clockSkew, "clockSkew must not be null");
		if (clockSkew.isNegative())
		{
			throw new IllegalArgumentException("clockSkew must not be negative");
		}
		expectedAudiences = Set.copyOf(Objects.requireNonNull(expectedAudiences, "expectedAudiences must not be null"));
		expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer must not be null")
		                        .map(value -> ValidationUtility.requireNonBlank(value,
				                        "expectedIssuer must not be blank"));
	}
}
