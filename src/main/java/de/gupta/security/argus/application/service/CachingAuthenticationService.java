package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.utility.TokenHasher;

import java.time.Instant;
import java.util.Optional;

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
		// TODO: convert to Unfolding chain with transformation steps
		final String hash = TokenHasher.sha256Hex(token);

		final Optional<AuthenticationResult> cached = cache.get(hash);
		if (cached.isPresent())
		{
			return cached.get();
		}

		final AuthenticationResult result = delegate.authenticate(token);

		final Instant expiresAt = resolveExpiresAt(result);
		if (shouldCache(result))
		{
			cache.put(hash, result, expiresAt);
		}

		return result;
	}

	private static boolean shouldCache(final AuthenticationResult result)
	{
		// TODO: 2 branches same. why cache failure too?
		return switch (result)
		{
			case AuthenticationSuccess _ -> true;
			case AuthenticationNotCurrent _ -> false;
			default -> true;
		};
	}

	private static Instant resolveExpiresAt(final AuthenticationResult result)
	{
		// TODO: use switch
		if (result instanceof AuthenticationSuccess success)
		{
			return success.identity()
			              .expiresAt()
			              .orElse(Instant.MAX);
		}
		return Instant.MAX;
	}

	private CachingAuthenticationService(
			final AuthenticationService delegate,
			final TokenAuthenticationCache cache)
	{
		this.delegate = delegate;
		this.cache = cache;
	}
}