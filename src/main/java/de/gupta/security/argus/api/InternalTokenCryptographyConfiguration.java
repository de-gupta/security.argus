package de.gupta.security.argus.api;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

// TODO: if this is supposed to be an internal inerface then why is it public in an exported package? everyeone can see this
// if this is related to hermes "inernal token", then we are doing a bad job by exposing this and leaking mechanics.
// Either very few such things should be taken from the consumer or argus should have sensible defaults or even generate keys itself based on some logic
// or would that be not secure?
public sealed interface InternalTokenCryptographyConfiguration
		permits InternalTokenCryptographyConfiguration.Hmac, InternalTokenCryptographyConfiguration.Rsa,
		        InternalTokenCryptographyConfiguration.Ec
{
	record Hmac(String issuerSecret) implements InternalTokenCryptographyConfiguration
	{
		public static Hmac of(final String issuerSecret)
		{
			return new Hmac(issuerSecret);
		}

		public Hmac
		{
			issuerSecret = requireNonBlank(issuerSecret, "issuerSecret must not be blank");
		}
	}

	record Rsa(RSAPrivateKey issuerPrivateKey, RSAPublicKey issuerPublicKey)
			implements InternalTokenCryptographyConfiguration
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

	record Ec(ECPrivateKey issuerPrivateKey, ECPublicKey issuerPublicKey)
			implements InternalTokenCryptographyConfiguration
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

	private static String requireNonBlank(final String value, final String message)
	{
		if (value == null || value.isBlank())
		{
			throw new IllegalArgumentException(message);
		}
		return value;
	}
}