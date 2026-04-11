package de.gupta.security.argus.api.cache;

import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Authentication cache configuration")
final class AuthenticationCacheConfigurationTest
{
	@Nested
	@DisplayName("factory methods")
	final class FactoryMethods
	{
		@Test
		void shouldCreateExplicitConfiguration()
		{
			final AuthenticationCacheConfiguration configuration = AuthenticationCacheConfiguration.of(
					42L,
					Duration.ofMinutes(2),
					Duration.ofSeconds(15));

			assertThat(configuration.maximumSize()).isEqualTo(42L);
			assertThat(configuration.successTimeToLive()).isEqualTo(Duration.ofMinutes(2));
			assertThat(configuration.failureTimeToLive()).isEqualTo(Duration.ofSeconds(15));
		}

		@Test
		void shouldProvideDefaults()
		{
			final AuthenticationCacheConfiguration configuration = AuthenticationCacheConfiguration.withDefaults();

			assertThat(configuration.maximumSize()).isEqualTo(10_000L);
			assertThat(configuration.successTimeToLive()).isEqualTo(Duration.ofMinutes(5));
			assertThat(configuration.failureTimeToLive()).isEqualTo(Duration.ofSeconds(30));
		}

		@Test
		void shouldExposeSingletonNoOpCache()
		{
			final TokenAuthenticationCache cache = TokenAuthenticationCache.noOp();
			final InvalidCredential failure = InvalidCredential.of(InvalidCredentialReason.INVALID_SIGNATURE);

			cache.put("hash-1", failure, Instant.MAX);
			cache.invalidateBySubject("subject-1");

			assertThat(TokenAuthenticationCache.noOp()).isSameAs(cache);
			assertThat(cache.get("hash-1")).isEmpty();
		}
	}

	@Nested
	@DisplayName("validation")
	final class Validation
	{
		@ParameterizedTest
		@ValueSource(longs = {0L, -1L})
		void shouldRejectNonPositiveMaximumSize(final long maximumSize)
		{
			assertThatThrownBy(() -> AuthenticationCacheConfiguration.of(
					maximumSize,
					Duration.ofMinutes(1),
					Duration.ofSeconds(30)))
					.isInstanceOf(IllegalArgumentException.class)
					.hasMessage("maximumSize must be positive");
		}

		@Test
		void shouldRejectNullSuccessTimeToLive()
		{
			assertThatThrownBy(() -> AuthenticationCacheConfiguration.of(1L, null, Duration.ofSeconds(30)))
					.isInstanceOf(NullPointerException.class)
					.hasMessage("successTimeToLive must not be null");
		}

		@Test
		void shouldRejectNullFailureTimeToLive()
		{
			assertThatThrownBy(() -> AuthenticationCacheConfiguration.of(1L, Duration.ofMinutes(1), null))
					.isInstanceOf(NullPointerException.class)
					.hasMessage("failureTimeToLive must not be null");
		}

		@ParameterizedTest
		@ValueSource(longs = {0L, -1L})
		void shouldRejectNonPositiveSuccessTimeToLive(final long seconds)
		{
			assertThatThrownBy(() -> AuthenticationCacheConfiguration.of(
					1L,
					Duration.ofSeconds(seconds),
					Duration.ofSeconds(30)))
					.isInstanceOf(IllegalArgumentException.class)
					.hasMessage("successTimeToLive must be positive");
		}

		@ParameterizedTest
		@ValueSource(longs = {0L, -1L})
		void shouldRejectNonPositiveFailureTimeToLive(final long seconds)
		{
			assertThatThrownBy(() -> AuthenticationCacheConfiguration.of(
					1L,
					Duration.ofMinutes(1),
					Duration.ofSeconds(seconds)))
					.isInstanceOf(IllegalArgumentException.class)
					.hasMessage("failureTimeToLive must be positive");
		}
	}
}
