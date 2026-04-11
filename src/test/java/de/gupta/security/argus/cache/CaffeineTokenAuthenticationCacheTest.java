package de.gupta.security.argus.cache;

import de.gupta.security.argus.api.cache.AuthenticationCacheConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.support.TestAuthenticationResults;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.*;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CaffeineTokenAuthenticationCache")
final class CaffeineTokenAuthenticationCacheTest
{
	@Test
	void shouldExpireSuccessAtTokenExpiryWhenSoonerThanConfiguredTtl() throws InterruptedException
	{
		final MutableClock clock = new MutableClock(Instant.parse("2026-04-09T12:00:00Z"));
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(10L, Duration.ofSeconds(1), Duration.ofSeconds(1)),
				clock);
		final AuthenticationSuccess success = TestAuthenticationResults.success("subject-success-expiry");

		cache.put("hash-success-expiry", success, clock.instant().plusMillis(60));

		assertThat(cache.get("hash-success-expiry")).containsSame(success);
		Thread.sleep(120L);
		assertThat(cache.get("hash-success-expiry")).isEmpty();
	}

	@Test
	void shouldExpireSuccessAtConfiguredTimeToLiveWhenTokenLivesLonger() throws InterruptedException
	{
		final MutableClock clock = new MutableClock(Instant.parse("2026-04-09T12:00:00Z"));
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(10L, Duration.ofMillis(60), Duration.ofSeconds(1)),
				clock);
		final AuthenticationSuccess success = TestAuthenticationResults.success("subject-success-config");

		cache.put("hash-success-config", success, clock.instant().plus(Duration.ofMinutes(30)));

		assertThat(cache.get("hash-success-config")).containsSame(success);
		Thread.sleep(120L);
		assertThat(cache.get("hash-success-config")).isEmpty();
	}

	@Test
	void shouldRespectUpdatedExpiryForExistingHash() throws InterruptedException
	{
		final MutableClock clock = new MutableClock(Instant.parse("2026-04-09T12:00:00Z"));
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(10L, Duration.ofSeconds(1), Duration.ofSeconds(1)),
				clock);
		final AuthenticationSuccess success = TestAuthenticationResults.success("subject-update");

		cache.put("hash-update", success, clock.instant().plusMillis(40));
		Thread.sleep(20L);
		clock.advance(Duration.ofMillis(20));
		cache.put("hash-update", success, clock.instant().plusMillis(160));

		Thread.sleep(50L);
		assertThat(cache.get("hash-update")).containsSame(success);
		Thread.sleep(150L);
		assertThat(cache.get("hash-update")).isEmpty();
	}

	@Test
	void shouldCacheFailuresForFailureTimeToLiveWithoutExtendingOnRead() throws InterruptedException
	{
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(10L, Duration.ofSeconds(1), Duration.ofMillis(80)));
		final InvalidCredential failure = InvalidCredential.of(InvalidCredentialReason.INVALID_SIGNATURE);

		cache.put("hash-failure-ttl", failure, Instant.MAX);

		assertThat(cache.get("hash-failure-ttl")).containsSame(failure);
		Thread.sleep(50L);
		assertThat(cache.get("hash-failure-ttl")).containsSame(failure);
		Thread.sleep(50L);
		assertThat(cache.get("hash-failure-ttl")).isEmpty();
	}

	@Test
	void shouldInvalidateEntriesBySubject()
	{
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(10L, Duration.ofSeconds(1), Duration.ofSeconds(1)));
		final AuthenticationSuccess success = TestAuthenticationResults.success("subject-invalidate");

		cache.put("hash-invalidate", success, Instant.MAX);
		cache.invalidateBySubject("subject-invalidate");
		cache.invalidateBySubject("subject-missing");

		assertThat(cache.get("hash-invalidate")).isEmpty();
	}

	@Test
	void shouldIgnoreFailureEntriesDuringSubjectInvalidation()
	{
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(10L, Duration.ofSeconds(1), Duration.ofSeconds(1)));
		final InvalidCredential failure = InvalidCredential.of(InvalidCredentialReason.INVALID_SIGNATURE);

		cache.put("hash-failure-subject", failure, Instant.MAX);
		cache.invalidateBySubject("subject-failure");

		assertThat(cache.get("hash-failure-subject")).containsSame(failure);
	}

	@Test
	void shouldInvalidateLatestEntryWhenMultipleHashesShareTheSameSubject()
	{
		final TokenAuthenticationCache cache = CaffeineTokenAuthenticationCache.create(
				AuthenticationCacheConfiguration.of(1L, Duration.ofSeconds(1), Duration.ofSeconds(1)));
		final AuthenticationSuccess first = TestAuthenticationResults.success("subject-evicted");
		final AuthenticationSuccess second = TestAuthenticationResults.success("subject-evicted");

		cache.put("hash-old", first, Instant.MAX);
		cache.put("hash-new", second, Instant.MAX);
		cache.invalidateBySubject("subject-evicted");

		assertThat(cache.get("hash-new")).isEmpty();
	}

	private static final class MutableClock extends Clock
	{
		private Instant current;

		@Override
		public ZoneId getZone()
		{
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(final ZoneId zone)
		{
			return this;
		}

		@Override
		public Instant instant()
		{
			return current;
		}

		private void advance(final Duration duration)
		{
			current = current.plus(duration);
		}

		private MutableClock(final Instant current)
		{
			this.current = current;
		}
	}
}