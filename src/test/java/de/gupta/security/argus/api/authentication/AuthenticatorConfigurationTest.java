package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("AuthenticatorConfiguration")
@TestInstance(PER_CLASS)
final class AuthenticatorConfigurationTest
{
    @Nested
    @DisplayName("as factory method")
    @TestInstance(PER_CLASS)
    final class FactoryMethod
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldCreateWithExplicitClock(final FactoryCase input)
        {
            final AuthenticatorConfiguration<String> configuration = AuthenticatorConfiguration.of(
                    input.upstreamTrustConfiguration(),
                    input.authenticatedTokenContract(),
                    input.authenticatedTokenMintingConfiguration(),
                    input.authenticatedTokenVerificationConfiguration(),
                    input.identityMappingConfiguration(),
                    input.clock());

            assertThat(configuration.upstreamTrustConfiguration()).isEqualTo(input.upstreamTrustConfiguration());
            assertThat(configuration.authenticatedTokenContract()).isEqualTo(input.authenticatedTokenContract());
            assertThat(configuration.authenticatedTokenMintingConfiguration())
                    .isEqualTo(input.authenticatedTokenMintingConfiguration());
            assertThat(configuration.authenticatedTokenVerificationConfiguration())
                    .isEqualTo(input.authenticatedTokenVerificationConfiguration());
            assertThat(configuration.identityMappingConfiguration()).isEqualTo(input.identityMappingConfiguration());
            assertThat(configuration.clock()).isEqualTo(input.clock());
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("minimalCases")
        void shouldDefaultClockToSystemUtc(final MinimalFactoryCase input)
        {
            final AuthenticatorConfiguration<String> configuration = AuthenticatorConfiguration.of(
                    input.upstreamTrustConfiguration(),
                    input.authenticatedTokenContract(),
                    input.authenticatedTokenMintingConfiguration(),
                    input.authenticatedTokenVerificationConfiguration(),
                    input.identityMappingConfiguration());

            assertThat(configuration.clock().getZone()).isEqualTo(ZoneOffset.UTC);
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new FactoryCase("keeps split token settings and explicit clock",
                            upstreamTrustConfiguration(),
                            authenticatedTokenContract(),
                            authenticatedTokenMintingConfiguration(),
                            authenticatedTokenVerificationConfiguration(),
                            identityMappingConfiguration(),
                            clock()))
                         .map(Arguments::of);
        }

        private Stream<Arguments> minimalCases()
        {
            return Stream.of(new MinimalFactoryCase("uses UTC clock when omitted",
                            upstreamTrustConfiguration(),
                            authenticatedTokenContract(),
                            authenticatedTokenMintingConfiguration(),
                            authenticatedTokenVerificationConfiguration(),
                            identityMappingConfiguration()))
                         .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as canonical constructor")
    @TestInstance(PER_CLASS)
    final class CanonicalConstructor
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("nullCases")
        void shouldRejectNullComponents(final NullCase input)
        {
            assertThatThrownBy(() -> new AuthenticatorConfiguration<>(input.upstreamTrustConfiguration(),
                            input.authenticatedTokenContract(),
                            input.authenticatedTokenMintingConfiguration(),
                            input.authenticatedTokenVerificationConfiguration(),
                            input.identityMappingConfiguration(),
                            input.clock()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage(input.expectedMessage());
        }

        private Stream<Arguments> nullCases()
        {
            return Stream.of(
                            new NullCase("when upstream trust configuration is missing",
                                    null,
                                    authenticatedTokenContract(),
                                    authenticatedTokenMintingConfiguration(),
                                    authenticatedTokenVerificationConfiguration(),
                                    identityMappingConfiguration(),
                                    clock(),
                                    "upstreamTrustConfiguration must not be null"),
                            new NullCase("when authenticated token contract is missing",
                                    upstreamTrustConfiguration(),
                                    null,
                                    authenticatedTokenMintingConfiguration(),
                                    authenticatedTokenVerificationConfiguration(),
                                    identityMappingConfiguration(),
                                    clock(),
                                    "authenticatedTokenContract must not be null"),
                            new NullCase("when authenticated token minting configuration is missing",
                                    upstreamTrustConfiguration(),
                                    authenticatedTokenContract(),
                                    null,
                                    authenticatedTokenVerificationConfiguration(),
                                    identityMappingConfiguration(),
                                    clock(),
                                    "authenticatedTokenMintingConfiguration must not be null"),
                            new NullCase("when authenticated token verification configuration is missing",
                                    upstreamTrustConfiguration(),
                                    authenticatedTokenContract(),
                                    authenticatedTokenMintingConfiguration(),
                                    null,
                                    identityMappingConfiguration(),
                                    clock(),
                                    "authenticatedTokenVerificationConfiguration must not be null"),
                            new NullCase("when identity mapping configuration is missing",
                                    upstreamTrustConfiguration(),
                                    authenticatedTokenContract(),
                                    authenticatedTokenMintingConfiguration(),
                                    authenticatedTokenVerificationConfiguration(),
                                    null,
                                    clock(),
                                    "identityMappingConfiguration must not be null"),
                            new NullCase("when clock is missing",
                                    upstreamTrustConfiguration(),
                                    authenticatedTokenContract(),
                                    authenticatedTokenMintingConfiguration(),
                                    authenticatedTokenVerificationConfiguration(),
                                    identityMappingConfiguration(),
                                    null,
                                    "clock must not be null"))
                         .map(Arguments::of);
        }
    }

    private static UpstreamTrustConfiguration upstreamTrustConfiguration()
    {
        return UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO), "upstream-secret");
    }

    private static AuthenticatedTokenContract authenticatedTokenContract()
    {
        return AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15));
    }

    private static AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration()
    {
        return AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of("minting-secret"));
    }

    private static AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration()
    {
        return AuthenticatedTokenVerificationConfiguration.of(
                TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"), Optional.of("argus")));
    }

    private static IdentityMappingConfiguration<String> identityMappingConfiguration()
    {
        return IdentityMappingConfiguration.of(externalId -> Optional.of("local-" + externalId),
                user -> user,
                user -> Set.of("ROLE_" + user.toUpperCase()),
                user -> (long) Objects.requireNonNull(user).length());
    }

    private static Clock clock()
    {
        return Clock.fixed(Instant.parse("2026-04-09T10:15:30Z"), ZoneOffset.UTC);
    }

    private record FactoryCase(String description,
                               UpstreamTrustConfiguration upstreamTrustConfiguration,
                               AuthenticatedTokenContract authenticatedTokenContract,
                               AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
                               AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
                               IdentityMappingConfiguration<String> identityMappingConfiguration,
                               Clock clock)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record MinimalFactoryCase(String description,
                                      UpstreamTrustConfiguration upstreamTrustConfiguration,
                                      AuthenticatedTokenContract authenticatedTokenContract,
                                      AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
                                      AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
                                      IdentityMappingConfiguration<String> identityMappingConfiguration)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record NullCase(String description,
                            UpstreamTrustConfiguration upstreamTrustConfiguration,
                            AuthenticatedTokenContract authenticatedTokenContract,
                            AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
                            AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
                            IdentityMappingConfiguration<String> identityMappingConfiguration,
                            Clock clock,
                            String expectedMessage)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }
}