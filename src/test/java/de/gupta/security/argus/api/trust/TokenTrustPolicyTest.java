package de.gupta.security.argus.api.trust;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class TokenTrustPolicyTest
{
	@Test
	void shouldRejectNegativeClockSkew()
	{
		assertThatThrownBy(() -> TokenTrustPolicy.of(Duration.ofSeconds(-1)))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clockSkew must not be negative");
	}

	@Test
	void shouldNotExposeCreateFactoryMethod()
	{
		assertThat(Arrays.stream(TokenTrustPolicy.class.getDeclaredMethods())
		                 .filter(method -> Modifier.isStatic(method.getModifiers()))
		                 .map(Method::getName))
				.doesNotContain("create");
	}
}