package de.gupta.security.argus.utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

// TODO: move to Athena medium term
public final class TokenHasher
{
	public static String sha256Hex(final String token)
	{
		try
		{
			final byte[] digest = MessageDigest.getInstance("SHA-256")
			                                   .digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new IllegalStateException("SHA-256 is not available on this JVM", e);
		}
	}

	private TokenHasher()
	{
	}
}