package de.gupta.security.argus.api;

import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

final class FactorySurfaceTest
{
	@Test
	void shouldExposeCreateOnlyOnAuthenticatorFactory()
	{
		assertThat(Arrays.stream(AuthenticatorFactory.class.getDeclaredMethods())
		                 .filter(method -> Modifier.isStatic(method.getModifiers()))
		                 .map(Method::getName))
				.contains("create");
	}
}
