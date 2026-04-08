package de.gupta.security.argus.api.trust;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

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
	}

	record Rsa(TokenTrustPolicy trustPolicy, RSAPublicKey issuerPublicKey) implements UpstreamTrustConfiguration
	{
		public static Rsa of(final TokenTrustPolicy trustPolicy, final RSAPublicKey issuerPublicKey)
		{
			return new Rsa(trustPolicy, issuerPublicKey);
		}
	}

	record Ec(TokenTrustPolicy trustPolicy, ECPublicKey issuerPublicKey) implements UpstreamTrustConfiguration
	{
		public static Ec of(final TokenTrustPolicy trustPolicy, final ECPublicKey issuerPublicKey)
		{
			return new Ec(trustPolicy, issuerPublicKey);
		}
	}
}