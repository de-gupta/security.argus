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
    @FunctionalInterface
    private interface PolicyFactory
    {
        TokenTrustPolicy create();
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
                    .as(input.description())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("clockSkew must not be negative");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("blankExpectedIssuerCases")
        void shouldRejectBlankExpectedIssuer(final ExpectedIssuerCase input)
        {
            assertThatThrownBy(() -> TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), input.expectedIssuer()))
                    .as(input.description())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("expectedIssuer must not be blank");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("nullFieldCases")
        void shouldRejectNullFields(final NullFieldCase input)
        {
            assertThatThrownBy(input::invoke)
                    .as(input.description())
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

    private record ExplicitFactoryCase(String description, PolicyFactory factory, TokenTrustPolicy expectedPolicy)
    {
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

    @Nested
    @DisplayName("as factory method")
    @TestInstance(PER_CLASS)
    final class FactoryMethod
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("explicitFactoryCases")
        void shouldCreateViaAllFactoryOverloads(final ExplicitFactoryCase input)
        {
            final TokenTrustPolicy policy = input.factory().create();

            assertThat(policy.clockSkew())
                    .as(input.description())
                    .isEqualTo(input.expectedPolicy().clockSkew());
            assertThat(policy.requireSubject())
                    .as(input.description())
                    .isEqualTo(input.expectedPolicy().requireSubject());
            assertThat(policy.expectedAudiences())
                    .as(input.description())
                    .isEqualTo(input.expectedPolicy().expectedAudiences());
            assertThat(policy.expectedIssuer())
                    .as(input.description())
                    .isEqualTo(input.expectedPolicy().expectedIssuer());
        }

        @Test
        void shouldApplyDefaultPolicyValues()
        {
            final TokenTrustPolicy policy = TokenTrustPolicy.of(Duration.ZERO);

            assertThat(policy.requireSubject())
                    .as("does not require a subject by default")
                    .isFalse();
            assertThat(policy.expectedAudiences())
                    .as("does not require audiences by default")
                    .isEmpty();
            assertThat(policy.expectedIssuer())
                    .as("does not require an issuer by default")
                    .isEmpty();
        }

        @Test
        void shouldCopyExpectedAudiencesDefensively()
        {
            final Set<String> audiences = new HashSet<>(Set.of("inventory"));

            final TokenTrustPolicy policy = TokenTrustPolicy.of(Duration.ZERO, true, audiences, Optional.of("argus"));

            audiences.add("reporting");

            assertThat(policy.expectedAudiences())
                    .as("keeps expected audiences stable after caller mutation")
                    .containsExactly("inventory");
        }

        private Stream<Arguments> explicitFactoryCases()
        {
            return Stream.of(
                                 new ExplicitFactoryCase("when issuer-free overload is used",
                                         () -> TokenTrustPolicy.of(Duration.ofSeconds(5), true, Set.of("inventory")),
                                         TokenTrustPolicy.of(Duration.ofSeconds(5),
                                                 true,
                                                 Set.of("inventory"),
                                                 Optional.empty())),
                                 new ExplicitFactoryCase("when subject-only overload is used",
                                         () -> TokenTrustPolicy.of(Duration.ofSeconds(5), true),
                                         TokenTrustPolicy.of(Duration.ofSeconds(5),
                                                 true,
                                                 Set.of(),
                                                 Optional.empty())))
                         .map(Arguments::of);
        }
    }
}