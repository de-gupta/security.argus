package de.gupta.security.argus.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.argus.api.cache.AuthenticationCacheConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

final class CaffeineTokenAuthenticationCache implements TokenAuthenticationCache
{
	private final Cache<String, CacheEntry> cache;
	private final Map<String, String> subjectToHash;
	// TODO: these 2 vars are not being used. design smell or future hooks?
	private final AuthenticationCacheConfiguration configuration;
	private final Clock clock;

	public static TokenAuthenticationCache create(
			final AuthenticationCacheConfiguration configuration,
			final Clock clock)
	{
		return new CaffeineTokenAuthenticationCache(configuration, clock);
	}

	public static TokenAuthenticationCache create(final AuthenticationCacheConfiguration configuration)
	{
		return create(configuration, Clock.systemUTC());
	}

	@Override
	public Optional<AuthenticationResult> get(final String tokenHash)
	{
		return Optional.ofNullable(cache.getIfPresent(tokenHash)).map(CacheEntry::result);
	}

	@Override
	public void put(final String tokenHash, final AuthenticationResult result, final Instant expiresAt)
	{
		cache.put(tokenHash, new CacheEntry(result, expiresAt));

		switch (result)
		{
			case AuthenticationSuccess success -> subjectToHash.put(success.identity().subject(), tokenHash);
			case AuthenticationResult _ ->
			{
			}
		}
	}

	@Override
	public void invalidateBySubject(final String subject)
	{
		final String hash = subjectToHash.remove(subject);
		Unfolding.beckon(hash)
		         .unlace(cache::invalidate);
	}

	private CaffeineTokenAuthenticationCache(
			final AuthenticationCacheConfiguration configuration,
			final Clock clock)
	{
		this.configuration = configuration;
		this.clock = clock;
		this.subjectToHash = new ConcurrentHashMap<>();
		// TODO: consider taking this out to a static helper method
		this.cache = Caffeine.newBuilder()
		                     .maximumSize(configuration.maximumSize())
		                     .expireAfter(new CacheEntryExpiry(configuration, clock))
		                     .removalListener((key, value, cause) ->
							 {
								 if (value != null && value.result() instanceof AuthenticationSuccess success)
								 {
									 subjectToHash.remove(success.identity().subject(), key);
								 }
							 })
		                     .build();
	}

	private record CacheEntry(AuthenticationResult result, Instant expiresAt)
	{
	}

	private record CacheEntryExpiry(
			AuthenticationCacheConfiguration configuration,
			Clock clock) implements Expiry<String, CacheEntry>
	{
		@Override
		public long expireAfterCreate(
				final String key,
				final CacheEntry entry,
				final long currentTime)
		{
			return computeTtlNanos(entry);
		}

		@Override
		public long expireAfterUpdate(
				final String key,
				final CacheEntry entry,
				final long currentTime,
				final long currentDuration)
		{
			return computeTtlNanos(entry);
		}

		@Override
		public long expireAfterRead(
				final String key,
				final CacheEntry entry,
				final long currentTime,
				final long currentDuration)
		{
			return currentDuration;
		}

		private static Duration minOf(final Duration a, final Duration b)
		{
			return a.compareTo(b) <= 0 ? a : b;
		}

		private long computeTtlNanos(final CacheEntry entry)
		{
			if (entry.result() instanceof AuthenticationSuccess)
			{
				final Instant now = clock.instant();
				final Duration tokenRemainingTtl = Duration.between(now, entry.expiresAt());
				final Duration effectiveTtl = minOf(configuration.successTimeToLive(), tokenRemainingTtl);
				return Math.max(0L, effectiveTtl.toNanos());
			}
			else
			{
				return configuration.failureTimeToLive().toNanos();
			}
		}
	}
}