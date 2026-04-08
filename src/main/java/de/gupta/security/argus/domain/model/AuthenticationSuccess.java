package de.gupta.security.argus.domain.model;

import de.gupta.security.themis.domain.model.NormalizedToken;

import java.util.Objects;

// TODO: we can't use NormalizedToken from themis - we can't leak that - we need to create a separate on in argus
// and it has to be an interface - it maybe backed by a private record impl but we need to expose an interface to the
// world. also it will (necessarily) delegate to (or wrap) the NormalizedToken from themis internally
public record AuthenticationSuccess(NormalizedToken token) implements AuthenticationResult
{
	public static AuthenticationSuccess of(final NormalizedToken token)
	{
		return new AuthenticationSuccess(token);
	}

	public AuthenticationSuccess
	{
		token = Objects.requireNonNull(token, "token must not be null");
	}
}