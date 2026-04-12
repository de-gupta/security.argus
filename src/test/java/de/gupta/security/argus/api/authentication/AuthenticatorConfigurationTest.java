package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
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
    private static IdentityMappingConfiguration<String, String> identityMappingConfiguration()
    {
        return IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
                externalId -> Optional.of("local-" + externalId),
                user -> user,
                user -> Set.of("ROLE_" + user.toUpperCase()),
				_ -> Instant.EPOCH);
    }

	private static UpstreamTrustConfiguration upstreamTrustConfiguration()
	{
		return UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO), "upstream-secret");
	}

    private Stream<Arguments> sharedMinimalFactoryCases()
    {
        return Stream.of(new MinimalFactoryCase("uses UTC clock when omitted",
                             upstreamTrustConfiguration(),
                             authenticatedTokenContract(),
                             authenticatedTokenMintingConfiguration(),
                             identityMappingConfiguration()))
                     .map(Arguments::of);
    }

    private Stream<Arguments> sharedNullCases()
    {
        return Stream.of(
                             new NullCase("when upstream trust configuration is missing",
                                     null,
                                     authenticatedTokenContract(),
                                     authenticatedTokenMintingConfiguration(),
                                     identityMappingConfiguration(),
                                     clock(),
                                     TokenAuthenticationCache.noOp(),
                                     "upstreamTrustConfiguration must not be null"),
                             new NullCase("when authenticated token contract is missing",
                                     upstreamTrustConfiguration(),
                                     null,
                                     authenticatedTokenMintingConfiguration(),
                                     identityMappingConfiguration(),
                                     clock(),
                                     TokenAuthenticationCache.noOp(),
                                     "authenticatedTokenContract must not be null"),
                             new NullCase("when authenticated token minting configuration is missing",
                                     upstreamTrustConfiguration(),
                                     authenticatedTokenContract(),
                                     null,
                                     identityMappingConfiguration(),
                                     clock(),
                                     TokenAuthenticationCache.noOp(),
                                     "authenticatedTokenMintingConfiguration must not be null"),
                             new NullCase("when identity mapping configuration is missing",
                                     upstreamTrustConfiguration(),
                                     authenticatedTokenContract(),
                                     authenticatedTokenMintingConfiguration(),
                                     null,
                                     clock(),
                                     TokenAuthenticationCache.noOp(),
                                     "identityMappingConfiguration must not be null"),
                             new NullCase("when clock is missing",
                                     upstreamTrustConfiguration(),
                                     authenticatedTokenContract(),
                                     authenticatedTokenMintingConfiguration(),
                                     identityMappingConfiguration(),
                                     null,
                                     TokenAuthenticationCache.noOp(),
                                     "clock must not be null"),
                             new NullCase("when token authentication cache is missing",
                                     upstreamTrustConfiguration(),
                                     authenticatedTokenContract(),
                                     authenticatedTokenMintingConfiguration(),
                                     identityMappingConfiguration(),
                                     clock(),
                                     null,
                                     "tokenAuthenticationCache must not be null"))
                     .map(Arguments::of);
    }

	private static AuthenticatedTokenContract authenticatedTokenContract()
	{
		return AuthenticatedTokenContract.of("argus", Set.of("inventory"), Duration.ofMinutes(15));
	}

	private static AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration()
	{
		return AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of("minting-secret"));
	}

    private Stream<Arguments> sharedFactoryCases()
    {
		return Stream.of(new FactoryCase("keeps token settings and explicit clock",
                             upstreamTrustConfiguration(),
                             authenticatedTokenContract(),
                             authenticatedTokenMintingConfiguration(),
                             identityMappingConfiguration(),
                             clock()))
                     .map(Arguments::of);
    }

	private record NullCase(String description,
	                        UpstreamTrustConfiguration upstreamTrustConfiguration,
	                        AuthenticatedTokenContract authenticatedTokenContract,
	                        AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
	                        IdentityMappingConfiguration<String, String> identityMappingConfiguration,
	                        Clock clock,
	                        TokenAuthenticationCache tokenAuthenticationCache,
	                        String expectedMessage)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

    @Nested
    @DisplayName("as factory method")
    @TestInstance(PER_CLASS)
    final class FactoryMethod
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("factoryCases")
        void shouldCreateWithExplicitClock(final FactoryCase input)
        {
            final AuthenticatorConfiguration<String, String> configuration = AuthenticatorConfiguration.of(
                    input.upstreamTrustConfiguration(),
                    input.authenticatedTokenContract(),
                    input.authenticatedTokenMintingConfiguration(),
                    input.identityMappingConfiguration(),
                    input.clock());

			assertThat(configuration.upstreamTrustConfiguration()).isEqualTo(input.upstreamTrustConfiguration());
			assertThat(configuration.authenticatedTokenContract()).isEqualTo(input.authenticatedTokenContract());
            assertThat(configuration.authenticatedTokenMintingConfiguration())
                    .isEqualTo(input.authenticatedTokenMintingConfiguration());
			assertThat(configuration.identityMappingConfiguration()).isEqualTo(input.identityMappingConfiguration());
			assertThat(configuration.clock()).isEqualTo(input.clock());
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("minimalFactoryCases")
        void shouldDefaultClockToSystemUtc(final MinimalFactoryCase input)
        {
            final AuthenticatorConfiguration<String, String> configuration = AuthenticatorConfiguration.of(
                    input.upstreamTrustConfiguration(),
                    input.authenticatedTokenContract(),
                    input.authenticatedTokenMintingConfiguration(),
                    input.identityMappingConfiguration());

			assertThat(configuration.clock().getZone()).isEqualTo(ZoneOffset.UTC);
        }

        private Stream<Arguments> factoryCases()
        {
            return sharedFactoryCases();
        }

        private Stream<Arguments> minimalFactoryCases()
        {
            return sharedMinimalFactoryCases();
        }
    }

    @Nested
    @DisplayName("as builder")
    @TestInstance(PER_CLASS)
    final class Builder
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("factoryCases")
        void shouldCreateWithExplicitClock(final FactoryCase input)
        {
            final AuthenticatorConfiguration<String, String> configuration =
                    AuthenticatorConfiguration.<String, String>builder()
                            .upstreamTrustConfiguration(input.upstreamTrustConfiguration())
                            .authenticatedTokenContract(input.authenticatedTokenContract())
                            .authenticatedTokenMintingConfiguration(input.authenticatedTokenMintingConfiguration())
                            .identityMappingConfiguration(input.identityMappingConfiguration())
                            .clock(input.clock())
                            .build();

			assertThat(configuration).isEqualTo(AuthenticatorConfiguration.of(
					input.upstreamTrustConfiguration(),
					input.authenticatedTokenContract(),
					input.authenticatedTokenMintingConfiguration(),
					input.identityMappingConfiguration(),
					input.clock()));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("minimalFactoryCases")
        void shouldDefaultClockToSystemUtc(final MinimalFactoryCase input)
        {
            final AuthenticatorConfiguration<String, String> configuration =
                    AuthenticatorConfiguration.<String, String>builder()
                            .upstreamTrustConfiguration(input.upstreamTrustConfiguration())
                            .authenticatedTokenContract(input.authenticatedTokenContract())
                            .authenticatedTokenMintingConfiguration(input.authenticatedTokenMintingConfiguration())
                            .identityMappingConfiguration(input.identityMappingConfiguration())
                            .build();

			assertThat(configuration.clock().getZone()).isEqualTo(ZoneOffset.UTC);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("nullCases")
        void shouldRejectNullComponentsWhenBuilding(final NullCase input)
        {
            assertThatThrownBy(() -> AuthenticatorConfiguration.<String, String>builder()
                                                               .upstreamTrustConfiguration(
                                                                       input.upstreamTrustConfiguration())
                                                               .authenticatedTokenContract(
                                                                       input.authenticatedTokenContract())
                                                               .authenticatedTokenMintingConfiguration(
                                                                       input.authenticatedTokenMintingConfiguration())
                                                               .identityMappingConfiguration(
                                                                       input.identityMappingConfiguration())
                                                               .clock(input.clock())
                                                               .tokenAuthenticationCache(
                                                                       input.tokenAuthenticationCache())
                                                               .build())
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage(input.expectedMessage());
        }

        private Stream<Arguments> factoryCases()
        {
            return sharedFactoryCases();
        }

        private Stream<Arguments> minimalFactoryCases()
        {
            return sharedMinimalFactoryCases();
        }

        private Stream<Arguments> nullCases()
        {
            return sharedNullCases();
        }
    }

    private static Clock clock()
    {
        return Clock.fixed(Instant.parse("2026-04-09T10:15:30Z"), ZoneOffset.UTC);
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
			assertThatThrownBy(() -> new AuthenticatorConfiguration<>(
					input.upstreamTrustConfiguration(),
					input.authenticatedTokenContract(),
					input.authenticatedTokenMintingConfiguration(),
					input.identityMappingConfiguration(),
					input.clock(),
					input.tokenAuthenticationCache()))
					.isInstanceOf(NullPointerException.class)
					.hasMessage(input.expectedMessage());
		}

		private Stream<Arguments> nullCases()
		{
			return sharedNullCases();
		}
	}

    private record FactoryCase(String description,
                               UpstreamTrustConfiguration upstreamTrustConfiguration,
                               AuthenticatedTokenContract authenticatedTokenContract,
                               AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
                               IdentityMappingConfiguration<String, String> identityMappingConfiguration,
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
                                      IdentityMappingConfiguration<String, String> identityMappingConfiguration)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }
}