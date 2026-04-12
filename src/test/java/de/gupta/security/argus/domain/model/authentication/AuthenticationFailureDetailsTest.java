package de.gupta.security.argus.domain.model.authentication;

import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailableReason;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolvedReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("Authentication failure details")
@TestInstance(PER_CLASS)
final class AuthenticationFailureDetailsTest
{
    @Nested
    @DisplayName("as string overload")
    @TestInstance(PER_CLASS)
    final class StringOverload
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldWrapStringsInFailureDetails(final StringOverloadCase input)
        {
            assertThat(input.failure().details())
                    .as(input.description())
                    .contains(FailureDetails.of(input.message()));
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new StringOverloadCase("for invalid credentials",
                                    InvalidCredential.of(InvalidCredentialReason.MALFORMED, "bad token"),
                                    "bad token"),
                            new StringOverloadCase("for identity resolution",
                                    IdentityNotResolved.of(IdentityNotResolvedReason.USER_NOT_FOUND, "user missing"),
                                    "user missing"),
                            new StringOverloadCase("for currentness checks",
									AuthenticationNotCurrent.of(AuthenticationNotCurrentReason.REVOKED,
											"token issued before last revocation"),
									"token issued before last revocation"),
                            new StringOverloadCase("for availability failures",
                                    AuthenticationUnavailable.of(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE,
                                            "downstream unavailable"),
                                    "downstream unavailable"))
                         .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as FailureDetails overload")
    @TestInstance(PER_CLASS)
    final class FailureDetailsOverload
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldStoreExplicitFailureDetails(final ExplicitDetailsCase input)
        {
            assertThat(input.failure().details())
                    .as(input.description())
                    .contains(input.details());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new ExplicitDetailsCase("for invalid credentials",
                                    InvalidCredential.of(InvalidCredentialReason.INVALID_SIGNATURE,
                                            FailureDetails.of("signature mismatch")),
                                    FailureDetails.of("signature mismatch")),
                            new ExplicitDetailsCase("for identity resolution",
                                    IdentityNotResolved.of(IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT,
                                            FailureDetails.of("user disabled")),
                                    FailureDetails.of("user disabled")),
                            new ExplicitDetailsCase("for currentness checks",
                                    AuthenticationNotCurrent.of(AuthenticationNotCurrentReason.REVOKED,
                                            FailureDetails.of("session revoked")),
                                    FailureDetails.of("session revoked")),
                            new ExplicitDetailsCase("for availability failures",
                                    AuthenticationUnavailable.of(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE,
                                            FailureDetails.of("service unavailable")),
                                    FailureDetails.of("service unavailable")))
                         .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as no-details overload")
    @TestInstance(PER_CLASS)
    final class EmptyDetailsOverload
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldLeaveDetailsEmpty(final EmptyDetailsCase input)
        {
            assertThat(input.failure().details())
                    .as(input.description())
                    .isEqualTo(Optional.empty());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new EmptyDetailsCase("for invalid credentials",
                                    InvalidCredential.of(InvalidCredentialReason.EXPIRED)),
                            new EmptyDetailsCase("for identity resolution",
                                    IdentityNotResolved.of(IdentityNotResolvedReason.USER_NOT_FOUND)),
                            new EmptyDetailsCase("for currentness checks",
									AuthenticationNotCurrent.of(AuthenticationNotCurrentReason.REVOKED)),
                            new EmptyDetailsCase("for availability failures",
                                    AuthenticationUnavailable.of(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE)))
                         .map(Arguments::of);
        }
    }

    private record StringOverloadCase(String description, AuthenticationFailure failure, String message)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record ExplicitDetailsCase(String description, AuthenticationFailure failure, FailureDetails details)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record EmptyDetailsCase(String description, AuthenticationFailure failure)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }
}