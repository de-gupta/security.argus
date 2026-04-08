package de.gupta.security.argus.api.token;

import java.util.Objects;

public record AuthenticatedTokenMintingConfiguration(TokenSignerConfiguration tokenSignerConfiguration)
{
	public static AuthenticatedTokenMintingConfiguration of(final TokenSignerConfiguration tokenSignerConfiguration)
	{
		return new AuthenticatedTokenMintingConfiguration(tokenSignerConfiguration);
	}

	public AuthenticatedTokenMintingConfiguration
	{
		Objects.requireNonNull(tokenSignerConfiguration,
				"tokenSignerConfiguration must not be null");
	}
}