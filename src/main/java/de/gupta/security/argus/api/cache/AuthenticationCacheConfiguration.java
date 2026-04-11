package de.gupta.security.argus.api.cache;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.argus.cache.CaffeineTokenAuthenticationCache;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

public record AuthenticationCacheConfiguration(
		long maximumSize,
		Duration successTimeToLive,
		Duration failureTimeToLive)
{
	public static AuthenticationCacheConfiguration of(
			final long maximumSize,
			final Duration successTimeToLive,
			final Duration failureTimeToLive)
	{
		return new AuthenticationCacheConfiguration(maximumSize, successTimeToLive, failureTimeToLive);
	}

	public static AuthenticationCacheConfiguration withDefaults()
	{
		final var maximumSize = 10_000L;
		final var successTimeToLive = Duration.ofMinutes(5);
		final var failureTimeToLive = Duration.ofSeconds(30);

		return new AuthenticationCacheConfiguration(maximumSize, successTimeToLive, failureTimeToLive);
	}

	public AuthenticationCacheConfiguration
	{
		Objects.requireNonNull(successTimeToLive, "successTimeToLive must not be null");
		Objects.requireNonNull(failureTimeToLive, "failureTimeToLive must not be null");

		Unfolding.beckon(maximumSize)
		         .discern(s -> s > 0, () -> new IllegalArgumentException("maximumSize must be positive"));

		Unfolding.beckon(successTimeToLive)
		         .discern(Duration::isPositive,
				         () -> new IllegalArgumentException("successTimeToLive must be positive"));
		Unfolding.beckon(failureTimeToLive)
		         .discern(Duration::isPositive,
				         () -> new IllegalArgumentException("failureTimeToLive must be positive"));
	}

	public TokenAuthenticationCache build()
	{
		return CaffeineTokenAuthenticationCache.create(this);
	}

	public TokenAuthenticationCache build(final Clock clock)
	{
		return CaffeineTokenAuthenticationCache.create(this, clock);
	}
}