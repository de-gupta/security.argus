package de.gupta.security.argus.application.service;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.augustus.api.TokenVersionVerifier;
import de.gupta.security.augustus.api.TokenVersionVerifierFactory;
import de.gupta.security.hermes.api.*;
import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.api.TokenVerifier;
import de.gupta.security.themis.api.TokenVerifierFactory;

final class LazyAuthenticationDependencies<ExternalIdentity, User>
{
	private final AuthenticatorConfiguration<ExternalIdentity, User> configuration;

	private volatile AuthenticationDependencies cachedDependencies;

	static <ExternalIdentity, User> LazyAuthenticationDependencies<ExternalIdentity, User> create(
			final AuthenticatorConfiguration<ExternalIdentity, User> configuration)
	{
		return new LazyAuthenticationDependencies<>(configuration);
	}

	AuthenticationDependencies summon()
	{
		final AuthenticationDependencies presentDependencies = cachedDependencies;
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

	private AuthenticationDependencies createDependencies()
	{
		return new AuthenticationDependencies(createTokenExchangeService(),
				createAuthenticatedTokenVerifier(),
				createTokenVersionVerifier());
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

	private TokenVerifier createAuthenticatedTokenVerifier()
	{
		final TokenVerificationConfiguration configuration = toThemisConfigurationWithClaimNames(
				this.configuration.authenticatedTokenVerificationConfiguration().trustPolicy(),
				this.configuration.authenticatedTokenContract().roleAttributeName(),
				this.configuration.authenticatedTokenContract().versionAttributeName());

		return switch (this.configuration.authenticatedTokenMintingConfiguration().tokenSignerConfiguration())
		{
			case TokenSignerConfiguration.Hmac hmac -> TokenVerifierFactory.hmac(configuration,
					hmac.issuerSecret(),
					this.configuration.clock());
			case TokenSignerConfiguration.Rsa rsa -> TokenVerifierFactory.rsa(configuration,
					rsa.issuerPublicKey(),
					this.configuration.clock());
			case TokenSignerConfiguration.Ec ec -> TokenVerifierFactory.ec(configuration,
					ec.issuerPublicKey(),
					this.configuration.clock());
		};
	}

	private TokenExchangeService createTokenExchangeService()
	{
		final TokenIssuancePolicy issuancePolicy =
				TokenIssuancePolicy.of(configuration.authenticatedTokenContract().issuer(),
						configuration.authenticatedTokenContract().audiences(),
						configuration.authenticatedTokenContract().timeToLive(),
						configuration.authenticatedTokenContract().roleAttributeName(),
						configuration.authenticatedTokenContract().versionAttributeName(),
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
				user -> configuration.identityMappingConfiguration().userTokenVersionResolver().resolveVersion(user),
				CustomClaimEnricher.none(),
				configuration.clock());

		return switch (configuration.authenticatedTokenMintingConfiguration().tokenSignerConfiguration())
		{
			case TokenSignerConfiguration.Hmac hmac -> TokenExchangeServiceFactory.hmac(createUpstreamTokenVerifier(),
					issuancePolicy,
					hmac.issuerSecret(),
					exchangeConfiguration);
			case TokenSignerConfiguration.Rsa rsa -> TokenExchangeServiceFactory.rsa(createUpstreamTokenVerifier(),
					issuancePolicy,
					rsa.issuerPrivateKey(),
					exchangeConfiguration);
			case TokenSignerConfiguration.Ec ec -> TokenExchangeServiceFactory.ec(createUpstreamTokenVerifier(),
					issuancePolicy,
					ec.issuerPrivateKey(),
					exchangeConfiguration);
		};
	}

	private TokenVersionVerifier<String, Long> createTokenVersionVerifier()
	{
		return TokenVersionVerifierFactory.create(
				configuration.identityMappingConfiguration().authenticatedSubjectVersionResolver()::resolveVersion);
	}

	private TokenVerificationConfiguration toThemisConfiguration(final TokenTrustPolicy policy)
	{
		return TokenVerificationConfiguration.of(toThemisPolicy(policy));
	}

	private TokenVerificationConfiguration toThemisConfigurationWithClaimNames(final TokenTrustPolicy policy,
	                                                                           final String rolesClaimName,
	                                                                           final String versionClaimName)
	{
		return TokenVerificationConfiguration.of(toThemisPolicy(policy), rolesClaimName, versionClaimName);
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