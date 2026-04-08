package de.gupta.security.argus.api;

import de.gupta.security.argus.utility.ValidationUtility;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public sealed interface UpstreamTrustConfiguration
		permits UpstreamTrustConfiguration.Hmac, UpstreamTrustConfiguration.Rsa, UpstreamTrustConfiguration.Ec
{
	TokenTrustPolicy trustPolicy();

	record Hmac(TokenTrustPolicy trustPolicy, String issuerSecret) implements UpstreamTrustConfiguration
	{
		public static Hmac of(final TokenTrustPolicy trustPolicy, final String issuerSecret)
		{
			return new Hmac(trustPolicy, issuerSecret);
		}

		public Hmac
		{
			trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy must not be null");
			issuerSecret = ValidationUtility.requireNonBlank(issuerSecret, "issuerSecret must not be blank");
		}
	}

	record Rsa(TokenTrustPolicy trustPolicy, RSAPublicKey issuerPublicKey) implements UpstreamTrustConfiguration
	{
		public static Rsa of(final TokenTrustPolicy trustPolicy, final RSAPublicKey issuerPublicKey)
		{
			return new Rsa(trustPolicy, issuerPublicKey);
		}

		public Rsa
		{
			trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy must not be null");
			issuerPublicKey = Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		}
	}

	record Ec(TokenTrustPolicy trustPolicy, ECPublicKey issuerPublicKey) implements UpstreamTrustConfiguration
	{
		public static Ec of(final TokenTrustPolicy trustPolicy, final ECPublicKey issuerPublicKey)
		{
			return new Ec(trustPolicy, issuerPublicKey);
		}

		public Ec
		{
			trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy must not be null");
			issuerPublicKey = Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		}
	}
}
