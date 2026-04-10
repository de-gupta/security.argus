package de.gupta.security.argus.api.cache;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

import java.time.Instant;
import java.util.Optional;

public interface TokenAuthenticationCache
{
	static TokenAuthenticationCache noOp()
	{
		return NoOpTokenAuthenticationCache.INSTANCE;
	}

	Optional<AuthenticationResult> get(final String tokenHash);

	void put(final String tokenHash, final AuthenticationResult result, final Instant expiresAt);

	void invalidateBySubject(final String subject);
}