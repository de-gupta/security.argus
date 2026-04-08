package de.gupta.security.argus.api;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("Factory surface")
@TestInstance(PER_CLASS)
final class FactorySurfaceTest
{
    @Nested
    @DisplayName("for value and configuration types")
    @TestInstance(PER_CLASS)
    final class ValueAndConfigurationTypes
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeOfWithoutCreate(final FactoryMethodCase input)
        {
            assertThat(staticMethodNamesOf(input.type()))
                    .contains("of")
                    .doesNotContain("create");
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new FactoryMethodCase("for authenticator configuration", AuthenticatorConfiguration.class),
                            new FactoryMethodCase("for authenticated token contract", AuthenticatedTokenContract.class),
                            new FactoryMethodCase("for authenticated token minting configuration",
                                    AuthenticatedTokenMintingConfiguration.class),
                            new FactoryMethodCase("for authenticated token verification configuration",
                                    AuthenticatedTokenVerificationConfiguration.class),
                            new FactoryMethodCase("for token trust policy", TokenTrustPolicy.class),
                            new FactoryMethodCase("for failure details", FailureDetails.class))
                         .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("for service factories")
    @TestInstance(PER_CLASS)
    final class ServiceFactories
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeCreate(final FactoryMethodCase input)
        {
            assertThat(staticMethodNamesOf(input.type())).contains("create");
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new FactoryMethodCase("for authenticator factory", AuthenticatorFactory.class))
                         .map(Arguments::of);
        }
    }

    private static Stream<String> staticMethodNamesOf(final Class<?> type)
    {
        return Arrays.stream(type.getDeclaredMethods())
                     .filter(method -> Modifier.isStatic(method.getModifiers()))
                     .map(Method::getName);
    }

    private record FactoryMethodCase(String description, Class<?> type)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }
}