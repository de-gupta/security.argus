package de.gupta.security.argus.domain.model.authentication;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class FailureDetailsTest
{
	@Test
	void shouldBehaveAsValueObject()
	{
		assertThat(FailureDetails.of("resolver unavailable"))
				.isEqualTo(new FailureDetails("resolver unavailable"));
	}
}