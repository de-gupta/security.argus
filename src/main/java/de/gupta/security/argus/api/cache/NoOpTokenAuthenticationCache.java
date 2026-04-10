package de.gupta.security.argus.api.cache;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

import java.time.Instant;
import java.util.Optional;

final class NoOpTokenAuthenticationCache implements TokenAuthenticationCache
{
	static final NoOpTokenAuthenticationCache INSTANCE = new NoOpTokenAuthenticationCache();

	@Override
	public Optional<AuthenticationResult> get(final String tokenHash)
	{
		return Optional.empty();
	}

	@Override
	public void put(final String tokenHash, final AuthenticationResult result, final Instant expiresAt)
	{
	}

	@Override
	public void invalidateBySubject(final String subject)
	{
	}

	private NoOpTokenAuthenticationCache()
	{
	}
}