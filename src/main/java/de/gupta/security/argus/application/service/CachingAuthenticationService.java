package de.gupta.security.argus.application.service;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.utility.TokenHasher;

import java.time.Instant;

final class CachingAuthenticationService implements AuthenticationService
{
	private final AuthenticationService delegate;
	private final TokenAuthenticationCache cache;

	static AuthenticationService wrap(final AuthenticationService delegate, final TokenAuthenticationCache cache)
	{
		return new CachingAuthenticationService(delegate, cache);
	}

	@Override
	public AuthenticationResult authenticate(final String token)
	{
		final String hash = TokenHasher.sha256Hex(token);
		return Unfolding.augur(cache.get(hash))
		                .ordain(() -> computeAndStore(hash, token));
	}

	private static boolean shouldCache(final AuthenticationResult result)
	{
		return !(result instanceof AuthenticationNotCurrent);
	}

	private static Instant resolveExpiresAt(final AuthenticationResult result)
	{
		return switch (result)
		{
			case AuthenticationSuccess success -> success.identity().expiresAt().orElse(Instant.MAX);
			default -> Instant.MAX;
		};
	}

	private AuthenticationResult computeAndStore(final String hash, final String token)
	{
		final AuthenticationResult result = delegate.authenticate(token);
		if (shouldCache(result))
		{
			cache.put(hash, result, resolveExpiresAt(result));
		}
		return result;
	}

	private CachingAuthenticationService(
			final AuthenticationService delegate,
			final TokenAuthenticationCache cache)
	{
		this.delegate = delegate;
		this.cache = cache;
	}
}