package de.gupta.security.argus.api;

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

		public Hmac
		{
			issuerSecret = ValidationUtility.requireNonBlank(issuerSecret, "issuerSecret must not be blank");
		}
	}

	record Rsa(RSAPrivateKey issuerPrivateKey, RSAPublicKey issuerPublicKey) implements TokenSignerConfiguration
	{
		public static Rsa of(final RSAPrivateKey issuerPrivateKey, final RSAPublicKey issuerPublicKey)
		{
			return new Rsa(issuerPrivateKey, issuerPublicKey);
		}

		public Rsa
		{
			issuerPrivateKey = Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey must not be null");
			issuerPublicKey = Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		}
	}

	record Ec(ECPrivateKey issuerPrivateKey, ECPublicKey issuerPublicKey) implements TokenSignerConfiguration
	{
		public static Ec of(final ECPrivateKey issuerPrivateKey, final ECPublicKey issuerPublicKey)
		{
			return new Ec(issuerPrivateKey, issuerPublicKey);
		}

		public Ec
		{
			issuerPrivateKey = Objects.requireNonNull(issuerPrivateKey, "issuerPrivateKey must not be null");
			issuerPublicKey = Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		}
	}
}
