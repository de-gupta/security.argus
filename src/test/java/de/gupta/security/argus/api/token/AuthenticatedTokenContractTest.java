package de.gupta.security.argus.api.token;

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

@DisplayName("AuthenticatedTokenContract")
@TestInstance(PER_CLASS)
final class AuthenticatedTokenContractTest
{
    @Nested
    @DisplayName("as factory method")
    @TestInstance(PER_CLASS)
    final class FactoryMethod
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
        void shouldApplyDefaultTokenShape()
        {
            final AuthenticatedTokenContract contract =
                    AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(10));

            assertThat(contract.roleAttributeName()).isEqualTo("roles");
            assertThat(contract.versionAttributeName()).isEqualTo("ver");
            assertThat(contract.upstreamIssuerAttributeName()).contains("upstream_iss");
            assertThat(contract.includeTokenId()).isTrue();
        }
    }

    @Nested
    @DisplayName("as canonical constructor")
    @TestInstance(PER_CLASS)
    final class CanonicalConstructor
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("nonPositiveTimeToLiveCases")
        void shouldRejectNonPositiveTimeToLive(final TimeToLiveCase input)
        {
            assertThatThrownBy(() -> AuthenticatedTokenContract.of("argus",
                            Set.of("inventory"),
                            input.timeToLive(),
                            "roles",
                            "ver",
                            Optional.of("upstream_iss"),
                            true))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("timeToLive must be positive");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("blankFieldCases")
        void shouldRejectBlankFields(final BlankFieldCase input)
        {
            assertThatThrownBy(input::invoke)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage(input.expectedMessage());
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("nullFieldCases")
        void shouldRejectNullFields(final NullFieldCase input)
        {
            assertThatThrownBy(input::invoke)
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage(input.expectedMessage());
        }

        private Stream<Arguments> nonPositiveTimeToLiveCases()
        {
            return Stream.of(new TimeToLiveCase("when time to live is zero", Duration.ZERO),
                            new TimeToLiveCase("when time to live is negative", Duration.ofSeconds(-1)))
                         .map(Arguments::of);
        }

        private Stream<Arguments> blankFieldCases()
        {
            return Stream.of(
                            new BlankFieldCase("when issuer is blank",
                                    () -> AuthenticatedTokenContract.of(" ",
                                            Set.of("inventory"),
                                            Duration.ofMinutes(10),
                                            "roles",
                                            "ver",
                                            Optional.of("upstream_iss"),
                                            true),
                                    "issuer must not be blank"),
                            new BlankFieldCase("when role attribute name is blank",
                                    () -> AuthenticatedTokenContract.of("argus",
                                            Set.of("inventory"),
                                            Duration.ofMinutes(10),
                                            " ",
                                            "ver",
                                            Optional.of("upstream_iss"),
                                            true),
                                    "roleAttributeName must not be blank"),
                            new BlankFieldCase("when version attribute name is blank",
                                    () -> AuthenticatedTokenContract.of("argus",
                                            Set.of("inventory"),
                                            Duration.ofMinutes(10),
                                            "roles",
                                            " ",
                                            Optional.of("upstream_iss"),
                                            true),
                                    "versionAttributeName must not be blank"),
                            new BlankFieldCase("when upstream issuer attribute name is blank",
                                    () -> AuthenticatedTokenContract.of("argus",
                                            Set.of("inventory"),
                                            Duration.ofMinutes(10),
                                            "roles",
                                            "ver",
                                            Optional.of(" "),
                                            true),
                                    "upstreamIssuerAttributeName must not be blank"))
                         .map(Arguments::of);
        }

        private Stream<Arguments> nullFieldCases()
        {
            return Stream.of(
                            new NullFieldCase("when audiences are missing",
                                    () -> AuthenticatedTokenContract.of("argus",
                                            null,
                                            Duration.ofMinutes(10),
                                            "roles",
                                            "ver",
                                            Optional.of("upstream_iss"),
                                            true),
                                    "audiences must not be null"),
                            new NullFieldCase("when time to live is missing",
                                    () -> AuthenticatedTokenContract.of("argus",
                                            Set.of("inventory"),
                                            null,
                                            "roles",
                                            "ver",
                                            Optional.of("upstream_iss"),
                                            true),
                                    "timeToLive must not be null"),
                            new NullFieldCase("when upstream issuer attribute name optional is missing",
                                    () -> AuthenticatedTokenContract.of("argus",
                                            Set.of("inventory"),
                                            Duration.ofMinutes(10),
                                            "roles",
                                            "ver",
                                            null,
                                            true),
                                    "upstreamIssuerAttributeName must not be null"))
                         .map(Arguments::of);
        }
    }

    private record TimeToLiveCase(String description, Duration timeToLive)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record BlankFieldCase(String description, ThrowingCall invocation, String expectedMessage)
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