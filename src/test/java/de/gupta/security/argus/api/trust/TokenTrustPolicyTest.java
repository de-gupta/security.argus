package de.gupta.security.argus.api.trust;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("TokenTrustPolicy")
@TestInstance(PER_CLASS)
final class TokenTrustPolicyTest
{
    @Nested
    @DisplayName("as factory method")
    @TestInstance(PER_CLASS)
    final class FactoryMethod
    {
        @Test
        void shouldApplyDefaultPolicyValues()
        {
            final TokenTrustPolicy policy = TokenTrustPolicy.of(Duration.ZERO);

            assertThat(policy.requireSubject()).isFalse();
            assertThat(policy.expectedAudiences()).isEmpty();
            assertThat(policy.expectedIssuer()).isEmpty();
        }

        @Test
        void shouldCopyExpectedAudiencesDefensively()
        {
            final Set<String> audiences = new HashSet<>(Set.of("inventory"));

            final TokenTrustPolicy policy = TokenTrustPolicy.of(Duration.ZERO, true, audiences, Optional.of("argus"));

            audiences.add("reporting");

            assertThat(policy.expectedAudiences()).containsExactly("inventory");
        }
    }

    @Nested
    @DisplayName("as canonical constructor")
    @TestInstance(PER_CLASS)
    final class CanonicalConstructor
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("negativeClockSkewCases")
        void shouldRejectNegativeClockSkew(final ClockSkewCase input)
        {
            assertThatThrownBy(() -> TokenTrustPolicy.of(input.clockSkew()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("clockSkew must not be negative");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("blankExpectedIssuerCases")
        void shouldRejectBlankExpectedIssuer(final ExpectedIssuerCase input)
        {
            assertThatThrownBy(() -> TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), input.expectedIssuer()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("expectedIssuer must not be blank");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("nullFieldCases")
        void shouldRejectNullFields(final NullFieldCase input)
        {
            assertThatThrownBy(input::invoke)
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage(input.expectedMessage());
        }

        private Stream<Arguments> negativeClockSkewCases()
        {
            return Stream.of(new ClockSkewCase("when clock skew is negative", Duration.ofSeconds(-1)))
                         .map(Arguments::of);
        }

        private Stream<Arguments> blankExpectedIssuerCases()
        {
            return Stream.of(new ExpectedIssuerCase("when expected issuer is blank", Optional.of(" ")))
                         .map(Arguments::of);
        }

        private Stream<Arguments> nullFieldCases()
        {
            return Stream.of(
                            new NullFieldCase("when clock skew is missing",
                                    () -> TokenTrustPolicy.of(null, true, Set.of("inventory"), Optional.of("argus")),
                                    "clockSkew must not be null"),
                            new NullFieldCase("when expected audiences are missing",
                                    () -> TokenTrustPolicy.of(Duration.ZERO, true, null, Optional.of("argus")),
                                    "expectedAudiences must not be null"),
                            new NullFieldCase("when expected issuer optional is missing",
                                    () -> TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), null),
                                    "expectedIssuer must not be null"))
                         .map(Arguments::of);
        }
    }

    private record ClockSkewCase(String description, Duration clockSkew)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record ExpectedIssuerCase(String description, Optional<String> expectedIssuer)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record NullFieldCase(String description, ThrowingCall invocation, String expectedMessage)
    {
        void invoke()
        {
            invocation.invoke();
        }

        @Override
        public String toString()
        {
            return description;
        }
    }

    @FunctionalInterface
    private interface ThrowingCall
    {
        void invoke();
    }
}