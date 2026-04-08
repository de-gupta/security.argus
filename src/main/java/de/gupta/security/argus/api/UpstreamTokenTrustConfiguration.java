package de.gupta.security.argus.api;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public sealed interface UpstreamTokenTrustConfiguration
		permits UpstreamTokenTrustConfiguration.Hmac, UpstreamTokenTrustConfiguration.Rsa,
		        UpstreamTokenTrustConfiguration.Ec
{
	TokenValidationPolicy validationPolicy();

	record Hmac(TokenValidationPolicy validationPolicy, String issuerSecret)
			implements UpstreamTokenTrustConfiguration
	{
		public static Hmac of(final TokenValidationPolicy validationPolicy, final String issuerSecret)
		{
			return new Hmac(validationPolicy, issuerSecret);
		}

		public Hmac
		{
			validationPolicy = Objects.requireNonNull(validationPolicy, "validationPolicy must not be null");
			issuerSecret = requireNonBlank(issuerSecret, "issuerSecret must not be blank");
		}
	}

	record Rsa(TokenValidationPolicy validationPolicy, RSAPublicKey issuerPublicKey)
			implements UpstreamTokenTrustConfiguration
	{
		public static Rsa of(final TokenValidationPolicy validationPolicy, final RSAPublicKey issuerPublicKey)
		{
			return new Rsa(validationPolicy, issuerPublicKey);
		}

		public Rsa
		{
			validationPolicy = Objects.requireNonNull(validationPolicy, "validationPolicy must not be null");
			issuerPublicKey = Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		}
	}

	record Ec(TokenValidationPolicy validationPolicy, ECPublicKey issuerPublicKey)
			implements UpstreamTokenTrustConfiguration
	{
		public static Ec of(final TokenValidationPolicy validationPolicy, final ECPublicKey issuerPublicKey)
		{
			return new Ec(validationPolicy, issuerPublicKey);
		}

		public Ec
		{
			validationPolicy = Objects.requireNonNull(validationPolicy, "validationPolicy must not be null");
			issuerPublicKey = Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		}
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
