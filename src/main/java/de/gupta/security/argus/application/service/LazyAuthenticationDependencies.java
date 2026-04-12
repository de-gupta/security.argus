package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.augustus.api.TokenRevocationVerifier;
import de.gupta.security.augustus.api.TokenRevocationVerifierFactory;
import de.gupta.security.hermes.api.*;
import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.api.TokenVerifier;
import de.gupta.security.themis.api.TokenVerifierFactory;

import java.time.Duration;

final class LazyAuthenticationDependencies<ExternalIdentity, User>
{
	private final AuthenticatorConfiguration<ExternalIdentity, User> configuration;

	private volatile AuthenticationDependencies<ExternalIdentity, User> cachedDependencies;

	static <ExternalIdentity, User> LazyAuthenticationDependencies<ExternalIdentity, User> create(
			final AuthenticatorConfiguration<ExternalIdentity, User> configuration)
	{
		return new LazyAuthenticationDependencies<>(configuration);
	}

	AuthenticationDependencies<ExternalIdentity, User> summon()
	{
		final AuthenticationDependencies<ExternalIdentity, User> presentDependencies = cachedDependencies;
		if (presentDependencies != null)
		{
			return presentDependencies;
		}

		synchronized (this)
		{
			if (cachedDependencies == null)
			{
				cachedDependencies = createDependencies();
			}
			return cachedDependencies;
		}
	}

	private AuthenticationDependencies<ExternalIdentity, User> createDependencies()
	{
		final TokenVerifier upstreamVerifier = createUpstreamTokenVerifier();
		return new AuthenticationDependencies<>(upstreamVerifier, createTokenExchangeService(upstreamVerifier),
				createTokenRevocationVerifier());
	}

	private TokenVerifier createUpstreamTokenVerifier()
	{
		return switch (configuration.upstreamTrustConfiguration())
		{
			case UpstreamTrustConfiguration.Hmac hmac ->
					TokenVerifierFactory.hmac(toThemisConfiguration(hmac.trustPolicy()),
							hmac.issuerSecret(),
							configuration.clock());
			case UpstreamTrustConfiguration.Rsa rsa ->
					TokenVerifierFactory.rsa(toThemisConfiguration(rsa.trustPolicy()),
							rsa.issuerPublicKey(),
							configuration.clock());
			case UpstreamTrustConfiguration.Ec ec -> TokenVerifierFactory.ec(toThemisConfiguration(ec.trustPolicy()),
					ec.issuerPublicKey(),
					configuration.clock());
		};
	}

	private TokenExchangeService createTokenExchangeService(final TokenVerifier upstreamVerifier)
	{
		final TokenIssuancePolicy issuancePolicy =
				TokenIssuancePolicy.of(configuration.authenticatedTokenContract().issuer(),
						configuration.authenticatedTokenContract().audiences(),
						configuration.authenticatedTokenContract().timeToLive(),
						configuration.authenticatedTokenContract().roleAttributeName(),
						configuration.authenticatedTokenContract().upstreamIssuerAttributeName(),
						configuration.authenticatedTokenContract().includeTokenId());

		final TokenExchangeConfiguration<User> exchangeConfiguration = TokenExchangeConfiguration.of(
				configuration.identityMappingConfiguration().externalIdentityAttributeName(),
				externalIdentity -> configuration.identityMappingConfiguration().externalIdentityAdapter()
				                                 .adapt(externalIdentity)
				                                 .flatMap(configuration.identityMappingConfiguration()
				                                                       .userResolver()::resolveUser),
				user -> configuration.identityMappingConfiguration().localSubjectResolver().resolveSubject(user),
				user -> configuration.identityMappingConfiguration().roleResolver().resolveRoles(user),
				CustomClaimEnricher.none(),
				configuration.clock());

		return switch (configuration.authenticatedTokenMintingConfiguration().tokenSignerConfiguration())
		{
			case TokenSignerConfiguration.Hmac hmac -> TokenExchangeServiceFactory.hmac(upstreamVerifier,
					issuancePolicy,
					hmac.issuerSecret(),
					exchangeConfiguration);
			case TokenSignerConfiguration.Rsa rsa -> TokenExchangeServiceFactory.rsa(upstreamVerifier,
					issuancePolicy,
					rsa.issuerPrivateKey(),
					exchangeConfiguration);
			case TokenSignerConfiguration.Ec ec -> TokenExchangeServiceFactory.ec(upstreamVerifier,
					issuancePolicy,
					ec.issuerPrivateKey(),
					exchangeConfiguration);
		};
	}

	private TokenRevocationVerifier<ExternalIdentity, User> createTokenRevocationVerifier()
	{
		final var identityMapping = configuration.identityMappingConfiguration();
		final Duration clockSkew = clockSkewFromUpstreamPolicy();

		return TokenRevocationVerifierFactory.create(
				externalIdentity -> identityMapping.userResolver().resolveUser(externalIdentity),
				user -> identityMapping.userRevocationResolver().lastRevokedAt(user),
				clockSkew);
	}

	private Duration clockSkewFromUpstreamPolicy()
	{
		return switch (configuration.upstreamTrustConfiguration())
		{
			case UpstreamTrustConfiguration.Hmac hmac -> hmac.trustPolicy().clockSkew();
			case UpstreamTrustConfiguration.Rsa rsa -> rsa.trustPolicy().clockSkew();
			case UpstreamTrustConfiguration.Ec ec -> ec.trustPolicy().clockSkew();
		};
	}

	private TokenVerificationConfiguration toThemisConfiguration(final TokenTrustPolicy policy)
	{
		return TokenVerificationConfiguration.of(toThemisPolicy(policy));
	}

	private TokenVerificationPolicy toThemisPolicy(final TokenTrustPolicy policy)
	{
		return TokenVerificationPolicy.of(policy.clockSkew(),
				policy.requireSubject(),
				policy.expectedAudiences(),
				policy.expectedIssuer());
	}

	private LazyAuthenticationDependencies(final AuthenticatorConfiguration<ExternalIdentity, User> configuration)
	{
		this.configuration = configuration;
	}
}