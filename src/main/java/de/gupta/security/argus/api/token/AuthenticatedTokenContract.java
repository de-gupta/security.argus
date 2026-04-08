package de.gupta.security.argus.api.token;

import de.gupta.security.argus.utility.ValidationUtility;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record AuthenticatedTokenContract(String issuer, Set<String> audiences, Duration timeToLive,
                                         String roleAttributeName, String versionAttributeName,
                                         Optional<String> upstreamIssuerAttributeName, boolean includeTokenId)
{
	public static AuthenticatedTokenContract of(final String issuer, final Set<String> audiences,
	                                            final Duration timeToLive, final String roleAttributeName,
	                                            final String versionAttributeName,
	                                            final Optional<String> upstreamIssuerAttributeName,
	                                            final boolean includeTokenId)
	{
		return new AuthenticatedTokenContract(issuer, audiences, timeToLive, roleAttributeName, versionAttributeName,
				upstreamIssuerAttributeName, includeTokenId);
	}

	public static AuthenticatedTokenContract of(final String issuer, final Set<String> audiences,
	                                            final Duration timeToLive)
	{
		return of(issuer, audiences, timeToLive, "roles", "ver", Optional.of("upstream_iss"), true);
	}

	public AuthenticatedTokenContract
	{
		issuer = ValidationUtility.requireNonBlank(issuer, "issuer must not be blank");
		audiences = Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null"));
		Objects.requireNonNull(timeToLive, "timeToLive must not be null");
		if (timeToLive.isNegative() || timeToLive.isZero())
		{
			throw new IllegalArgumentException("timeToLive must be positive");
		}
		roleAttributeName = ValidationUtility.requireNonBlank(roleAttributeName, "roleAttributeName must not be blank");
		versionAttributeName =
				ValidationUtility.requireNonBlank(versionAttributeName, "versionAttributeName must not be blank");
		upstreamIssuerAttributeName =
				Objects.requireNonNull(upstreamIssuerAttributeName, "upstreamIssuerAttributeName must not be null")
				       .map(value -> ValidationUtility.requireNonBlank(value,
							   "upstreamIssuerAttributeName must not be blank"));
	}
}