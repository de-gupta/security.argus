package de.gupta.security.argus.api;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

// TODO: again  huge class with bad to get an overview - break down and all these "internal" api exposure is a thorn
//  in my eye.
public record InternalTokenPolicy(String issuer,
                                  Set<String> audiences,
                                  Duration timeToLive,
                                  String roleClaimName,
                                  String versionClaimName,
                                  Optional<String> upstreamIssuerClaimName,
                                  boolean includeTokenId,
                                  TokenValidationPolicy validationPolicy)
{
	public static InternalTokenPolicy of(final String issuer,
	                                     final Set<String> audiences,
	                                     final Duration timeToLive,
	                                     final String roleClaimName,
	                                     final String versionClaimName,
	                                     final Optional<String> upstreamIssuerClaimName,
	                                     final boolean includeTokenId,
	                                     final TokenValidationPolicy validationPolicy)
	{
		return new InternalTokenPolicy(issuer,
				audiences,
				timeToLive,
				roleClaimName,
				versionClaimName,
				upstreamIssuerClaimName,
				includeTokenId,
				validationPolicy);
	}

	public static InternalTokenPolicy of(final String issuer,
	                                     final Set<String> audiences,
	                                     final Duration timeToLive)
	{
		return of(issuer,
				audiences,
				timeToLive,
				"roles",
				"ver",
				Optional.of("upstream_iss"),
				true,
				TokenValidationPolicy.of(Duration.ZERO, true, audiences, Optional.of(issuer)));
	}

	public InternalTokenPolicy
	{
		issuer = requireNonBlank(issuer, "issuer must not be blank");
		audiences = Set.copyOf(Objects.requireNonNull(audiences, "audiences must not be null"));
		timeToLive = Objects.requireNonNull(timeToLive, "timeToLive must not be null");
		if (timeToLive.isNegative() || timeToLive.isZero())
		{
			throw new IllegalArgumentException("timeToLive must be positive");
		}
		roleClaimName = requireNonBlank(roleClaimName, "roleClaimName must not be blank");
		versionClaimName = requireNonBlank(versionClaimName, "versionClaimName must not be blank");
		upstreamIssuerClaimName = Objects.requireNonNull(upstreamIssuerClaimName,
				"upstreamIssuerClaimName must not be null")
		                                 .map(value -> requireNonBlank(value,
				                                 "upstreamIssuerClaimName must not be blank"));
		validationPolicy = Objects.requireNonNull(validationPolicy, "validationPolicy must not be null");
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