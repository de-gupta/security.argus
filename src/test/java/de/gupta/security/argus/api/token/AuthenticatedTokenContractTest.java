package de.gupta.security.argus.api.token;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class AuthenticatedTokenContractTest
{
	@Test
	void shouldCopyAudiencesDefensively()
	{
		final Set<String> audiences = new HashSet<>(Set.of("inventory"));

		final AuthenticatedTokenContract contract =
				AuthenticatedTokenContract.of("argus", audiences, Duration.ofMinutes(10));

		audiences.add("reporting");

		assertThat(contract.audiences()).containsExactly("inventory");
	}

	@Test
	void shouldRejectZeroTimeToLive()
	{
		assertThatThrownBy(() -> AuthenticatedTokenContract.of("argus",
						Set.of("inventory"),
						Duration.ZERO,
						"roles",
						"ver",
						Optional.of("upstream_iss"),
						true))
				.isInstanceOf(IllegalArgumentException.class)
                .hasMessage("timeToLive must be positive");
	}

	@Test
	void shouldRejectNegativeTimeToLive()
	{
		assertThatThrownBy(() -> AuthenticatedTokenContract.of("argus",
						Set.of("inventory"),
						Duration.ofSeconds(-1),
						"roles",
						"ver",
						Optional.of("upstream_iss"),
						true))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("timeToLive must be positive");
	}
}
