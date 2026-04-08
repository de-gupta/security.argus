package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;

import java.time.Clock;
import java.util.Objects;

public record AuthenticatorConfiguration<ExternalIdentity, User>(
        UpstreamTrustConfiguration upstreamTrustConfiguration,
        AuthenticatedTokenContract authenticatedTokenContract,
        AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
        AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
        IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration,
        Clock clock)
{
    public static <ExternalIdentity, User> AuthenticatorConfiguration<ExternalIdentity, User> of(
            final UpstreamTrustConfiguration upstreamTrustConfiguration,
            final AuthenticatedTokenContract authenticatedTokenContract,
            final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
            final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
            final IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration,
            final Clock clock)
    {
        return new AuthenticatorConfiguration<>(upstreamTrustConfiguration,
                authenticatedTokenContract,
                authenticatedTokenMintingConfiguration,
                authenticatedTokenVerificationConfiguration,
                identityMappingConfiguration,
                clock);
    }

    public static <ExternalIdentity, User> AuthenticatorConfiguration<ExternalIdentity, User> of(
            final UpstreamTrustConfiguration upstreamTrustConfiguration,
            final AuthenticatedTokenContract authenticatedTokenContract,
            final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
            final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
            final IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration)
    {
        return of(upstreamTrustConfiguration,
                authenticatedTokenContract,
                authenticatedTokenMintingConfiguration,
                authenticatedTokenVerificationConfiguration,
                identityMappingConfiguration,
                Clock.systemUTC());
    }

    public static <ExternalIdentity, User> Builder<ExternalIdentity, User> builder()
    {
        return new Builder<>();
    }

    public AuthenticatorConfiguration
    {
        upstreamTrustConfiguration =
                Objects.requireNonNull(upstreamTrustConfiguration, "upstreamTrustConfiguration must not be null");
        authenticatedTokenContract = Objects.requireNonNull(authenticatedTokenContract,
                "authenticatedTokenContract must not be null");
        authenticatedTokenMintingConfiguration = Objects.requireNonNull(authenticatedTokenMintingConfiguration,
                "authenticatedTokenMintingConfiguration must not be null");
        authenticatedTokenVerificationConfiguration =
                Objects.requireNonNull(authenticatedTokenVerificationConfiguration,
                        "authenticatedTokenVerificationConfiguration must not be null");
        identityMappingConfiguration = Objects.requireNonNull(identityMappingConfiguration,
                "identityMappingConfiguration must not be null");
        clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public static final class Builder<ExternalIdentity, User>
    {
        private UpstreamTrustConfiguration upstreamTrustConfiguration;
        private AuthenticatedTokenContract authenticatedTokenContract;
        private AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration;
        private AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration;
        private IdentityMappingConfiguration<ExternalIdentity, User> identityMappingConfiguration;
        private Clock clock = Clock.systemUTC();

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

        public Builder<ExternalIdentity, User> authenticatedTokenVerificationConfiguration(
                final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration)
        {
            this.authenticatedTokenVerificationConfiguration = authenticatedTokenVerificationConfiguration;
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

        public AuthenticatorConfiguration<ExternalIdentity, User> build()
        {
            return new AuthenticatorConfiguration<>(upstreamTrustConfiguration,
                    authenticatedTokenContract,
                    authenticatedTokenMintingConfiguration,
                    authenticatedTokenVerificationConfiguration,
                    identityMappingConfiguration,
                    clock);
        }
    }
}