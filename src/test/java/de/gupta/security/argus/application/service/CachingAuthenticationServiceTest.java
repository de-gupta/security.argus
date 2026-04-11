package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.support.TestAuthenticationResults;
import de.gupta.security.argus.utility.TokenHasher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CachingAuthenticationService")
final class CachingAuthenticationServiceTest
{
	@Test
	void shouldReuseCachedResultAfterFirstAuthentication()
	{
		final RecordingCache cache = new RecordingCache();
		final AtomicInteger invocations = new AtomicInteger();
		final InvalidCredential failure = InvalidCredential.of(InvalidCredentialReason.INVALID_SIGNATURE);
		final AuthenticationService service = CachingAuthenticationService.wrap(_ ->
		{
			invocations.incrementAndGet();
			return failure;
		}, cache);

		final AuthenticationResult first = service.authenticate("token-1");
		final AuthenticationResult second = service.authenticate("token-1");

		assertThat(first).isSameAs(failure);
		assertThat(second).isSameAs(failure);
		assertThat(invocations).hasValue(1);
		assertThat(cache.getRequestedHashes()).containsExactly(TokenHasher.sha256Hex("token-1"),
				TokenHasher.sha256Hex("token-1"));
		assertThat(cache.putCalls()).isEqualTo(1);
		assertThat(cache.lastPutHash()).isEqualTo(TokenHasher.sha256Hex("token-1"));
		assertThat(cache.lastPutResult()).isSameAs(failure);
		assertThat(cache.lastPutExpiresAt()).isEqualTo(Instant.MAX);
	}

	@Test
	void shouldNotCacheCurrentnessFailures()
	{
		final RecordingCache cache = new RecordingCache();
		final AtomicInteger invocations = new AtomicInteger();
		final AuthenticationNotCurrent failure = AuthenticationNotCurrent.of(
				AuthenticationNotCurrentReason.VERSION_MISMATCH);
		final AuthenticationService service = CachingAuthenticationService.wrap(_ ->
		{
			invocations.incrementAndGet();
			return failure;
		}, cache);

		final AuthenticationResult first = service.authenticate("token-2");
		final AuthenticationResult second = service.authenticate("token-2");

		assertThat(first).isSameAs(failure);
		assertThat(second).isSameAs(failure);
		assertThat(invocations).hasValue(2);
		assertThat(cache.putCalls()).isZero();
		assertThat(cache.get(TokenHasher.sha256Hex("token-2"))).isEmpty();
	}

	@Test
	void shouldStoreSuccessWithIdentityExpiry()
	{
		final RecordingCache cache = new RecordingCache();
		final AuthenticationSuccess success = TestAuthenticationResults.success("local-user-123");
		final AuthenticationService service = CachingAuthenticationService.wrap(_ -> success, cache);

		final AuthenticationResult result = service.authenticate("token-3");

		assertThat(result).isSameAs(success);
		assertThat(cache.putCalls()).isEqualTo(1);
		assertThat(cache.lastPutResult()).isSameAs(success);
		assertThat(cache.lastPutExpiresAt()).isEqualTo(success.identity().expiresAt().orElseThrow());
	}

	private static final class RecordingCache implements TokenAuthenticationCache
	{
		private final Map<String, AuthenticationResult> entries = new HashMap<>();
		private final java.util.List<String> requestedHashes = new java.util.ArrayList<>();
		private int putCalls;
		private String lastPutHash;
		private AuthenticationResult lastPutResult;
		private Instant lastPutExpiresAt;

		@Override
		public Optional<AuthenticationResult> get(final String tokenHash)
		{
			requestedHashes.add(tokenHash);
			return Optional.ofNullable(entries.get(tokenHash));
		}

		@Override
		public void put(final String tokenHash, final AuthenticationResult result, final Instant expiresAt)
		{
			putCalls++;
			lastPutHash = tokenHash;
			lastPutResult = result;
			lastPutExpiresAt = expiresAt;
			entries.put(tokenHash, result);
		}

		@Override
		public void invalidateBySubject(final String subject)
		{
		}

		int putCalls()
		{
			return putCalls;
		}

		String lastPutHash()
		{
			return lastPutHash;
		}

		AuthenticationResult lastPutResult()
		{
			return lastPutResult;
		}

		Instant lastPutExpiresAt()
		{
			return lastPutExpiresAt;
		}

		java.util.List<String> getRequestedHashes()
		{
			return requestedHashes;
		}
	}
}