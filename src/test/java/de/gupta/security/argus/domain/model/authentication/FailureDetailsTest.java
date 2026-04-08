package de.gupta.security.argus.domain.model.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("FailureDetails")
@TestInstance(PER_CLASS)
final class FailureDetailsTest
{
    @Nested
    @DisplayName("as factory method")
    @TestInstance(PER_CLASS)
    final class FactoryMethod
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldCreateValueObjects(final FailureDetailsCase input)
        {
            assertThat(FailureDetails.of(input.message()))
                    .isEqualTo(new FailureDetails(input.message()));
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new FailureDetailsCase("for a short message", "resolver unavailable"),
                            new FailureDetailsCase("for a sentence", "downstream verification service timed out"))
                         .map(Arguments::of);
        }
    }

    private record FailureDetailsCase(String description, String message)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }
}