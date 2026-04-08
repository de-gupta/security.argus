package de.gupta.security.argus.api.token;

import de.gupta.security.argus.utility.ValidationUtility;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public sealed interface TokenSignerConfiguration
		permits TokenSignerConfiguration.Hmac, TokenSignerConfiguration.Rsa, TokenSignerConfiguration.Ec
{
	record Hmac(String issuerSecret) implements TokenSignerConfiguration
	{
		public static Hmac of(final String issuerSecret)
		{
			return new Hmac(issuerSecret);
		}
	}

	record Rsa(RSAPrivateKey issuerPrivateKey, RSAPublicKey issuerPublicKey) implements TokenSignerConfiguration
	{
		public static Rsa of(final RSAPrivateKey issuerPrivateKey, final RSAPublicKey issuerPublicKey)
		{
			return new Rsa(issuerPrivateKey, issuerPublicKey);
		}
	}

	record Ec(ECPrivateKey issuerPrivateKey, ECPublicKey issuerPublicKey) implements TokenSignerConfiguration
	{
		public static Ec of(final ECPrivateKey issuerPrivateKey, final ECPublicKey issuerPublicKey)
		{
			return new Ec(issuerPrivateKey, issuerPublicKey);
		}
	}
}