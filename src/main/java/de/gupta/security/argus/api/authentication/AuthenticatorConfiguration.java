package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;

import java.time.Clock;
import java.util.Objects;

public record AuthenticatorConfiguration<ExternalIdentity, User>(
        UpstreamTrustConfiguration upstreamTrustConfiguration,
        AuthenticatedTokenContract authenticatedTokenContract,
        AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
        IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration,
        Clock clock,
        TokenAuthenticationCache tokenAuthenticationCache)
{
    public static <ExternalIdentity, User> AuthenticatorConfiguration<ExternalIdentity, User> of(
            final UpstreamTrustConfiguration upstreamTrustConfiguration,
            final AuthenticatedTokenContract authenticatedTokenContract,
            final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
            final IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration,
            final Clock clock,
            final TokenAuthenticationCache tokenAuthenticationCache)
    {
        return new AuthenticatorConfiguration<>(upstreamTrustConfiguration,
                authenticatedTokenContract,
                authenticatedTokenMintingConfiguration,
                identityMappingConfiguration,
                clock,
                tokenAuthenticationCache);
    }

    public static <ExternalIdentity, User> AuthenticatorConfiguration<ExternalIdentity, User> of(
            final UpstreamTrustConfiguration upstreamTrustConfiguration,
            final AuthenticatedTokenContract authenticatedTokenContract,
            final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
            final IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration,
            final Clock clock)
    {
        return of(upstreamTrustConfiguration,
                authenticatedTokenContract,
                authenticatedTokenMintingConfiguration,
                identityMappingConfiguration,
                clock,
                TokenAuthenticationCache.noOp());
    }

    public static <ExternalIdentity, User> AuthenticatorConfiguration<ExternalIdentity, User> of(
            final UpstreamTrustConfiguration upstreamTrustConfiguration,
            final AuthenticatedTokenContract authenticatedTokenContract,
            final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
            final IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration)
    {
        return of(upstreamTrustConfiguration,
                authenticatedTokenContract,
                authenticatedTokenMintingConfiguration,
                identityMappingConfiguration,
                Clock.systemUTC());
    }

    public static <ExternalIdentity, User> Builder<ExternalIdentity, User> builder()
    {
        return new Builder<>();
    }

    public AuthenticatorConfiguration
    {
        Objects.requireNonNull(upstreamTrustConfiguration, "upstreamTrustConfiguration must not be null");
        Objects.requireNonNull(authenticatedTokenContract, "authenticatedTokenContract must not be null");
        Objects.requireNonNull(authenticatedTokenMintingConfiguration,
                "authenticatedTokenMintingConfiguration must not be null");
        Objects.requireNonNull(identityMappingConfiguration, "identityMappingConfiguration must not be null");
        Objects.requireNonNull(clock, "clock must not be null");
        Objects.requireNonNull(tokenAuthenticationCache, "tokenAuthenticationCache must not be null");
    }

    public static final class Builder<ExternalIdentity, User>
    {
        private UpstreamTrustConfiguration upstreamTrustConfiguration;
        private AuthenticatedTokenContract authenticatedTokenContract;
        private AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration;
        private IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration;
        private Clock clock = Clock.systemUTC();
        private TokenAuthenticationCache tokenAuthenticationCache = TokenAuthenticationCache.noOp();

        private Builder()
        {
        }

        public Builder<ExternalIdentity, User> upstreamTrustConfiguration(
                final UpstreamTrustConfiguration upstreamTrustConfiguration)
        {
            this.upstreamTrustConfiguration = upstreamTrustConfiguration;
            return this;
        }

        public Builder<ExternalIdentity, User> authenticatedTokenContract(
                final AuthenticatedTokenContract authenticatedTokenContract)
        {
            this.authenticatedTokenContract = authenticatedTokenContract;
            return this;
        }

        public Builder<ExternalIdentity, User> authenticatedTokenMintingConfiguration(
                final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration)
        {
            this.authenticatedTokenMintingConfiguration = authenticatedTokenMintingConfiguration;
            return this;
        }

        public Builder<ExternalIdentity, User> identityMappingConfiguration(
                final IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration)
        {
            this.identityMappingConfiguration = identityMappingConfiguration;
            return this;
        }

        public Builder<ExternalIdentity, User> clock(final Clock clock)
        {
            this.clock = clock;
            return this;
        }

        public Builder<ExternalIdentity, User> tokenAuthenticationCache(
                final TokenAuthenticationCache tokenAuthenticationCache)
        {
            this.tokenAuthenticationCache = tokenAuthenticationCache;
            return this;
        }

        public AuthenticatorConfiguration<ExternalIdentity, User> build()
        {
            return new AuthenticatorConfiguration<>(upstreamTrustConfiguration,
                    authenticatedTokenContract,
                    authenticatedTokenMintingConfiguration,
                    identityMappingConfiguration,
                    clock,
                    tokenAuthenticationCache);
        }
    }
}