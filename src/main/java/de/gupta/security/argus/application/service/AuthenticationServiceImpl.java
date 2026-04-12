package de.gupta.security.argus.application.service;

import de.gupta.aletheia.trials.Fallible;
import de.gupta.aletheia.trials.Portent;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.augustus.domain.model.TokenIssuance;
import de.gupta.security.augustus.domain.model.TokenRevocationVerificationFailure;
import de.gupta.security.augustus.domain.model.TokenRevocationVerificationSuccess;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.hermes.domain.model.ExchangeSuccess;
import de.gupta.security.themis.domain.model.NormalizedToken;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationSuccess;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

final class AuthenticationServiceImpl<ExternalIdentity, User> implements AuthenticationService
{
	private final AuthenticatorConfiguration<ExternalIdentity, User> configuration;
	private final AuthenticationResultAdapter resultAdapter;
	private final LazyAuthenticationDependencies<ExternalIdentity, User> dependencies;

	static <ExternalIdentity, User> AuthenticationService create(
			final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
			final AuthenticationResultAdapter resultMapper)
	{
		return new AuthenticationServiceImpl<>(configuration, resultMapper,
				LazyAuthenticationDependencies.create(configuration));
	}

	@Override
	public AuthenticationResult authenticate(final String token)
	{
		return Fallible.beckon(token)
		               .metamorphose(this::authenticatePipeline, exceptional())
		               .coronate(Function.identity(), exception -> resultAdapter.unavailable(exception.getMessage()));
	}

	private AuthenticationResult authenticatePipeline(final String token)
	{
		final AuthenticationDependencies<ExternalIdentity, User> authDeps = dependencies.summon();

		// Step 1: Verify upstream token cryptographically
		final var verificationResult = authDeps.upstreamTokenVerifier().verify(token);

		return switch (verificationResult)
		{
			case VerificationSuccess success -> checkCurrentness(authDeps, success.token(), token);
			case VerificationFailure failure -> resultAdapter.invalidCredential(failure);
		};
	}

	private AuthenticationResult checkCurrentness(
			final AuthenticationDependencies<ExternalIdentity, User> authDeps,
			final NormalizedToken upstreamToken,
			final String rawToken)
	{
		// Step 2: Require iat claim for revocation check
		final Optional<Instant> issuedAt = upstreamToken.issuedAt();
		if (issuedAt.isEmpty())
		{
			return resultAdapter.missingIssuedAt();
		}

		// Adapt the subject string to the typed ExternalIdentity
		final Optional<ExternalIdentity> externalIdentity =
				configuration.identityMappingConfiguration()
				             .externalIdentityAdapter()
				             .adapt(upstreamToken.subject());

		if (externalIdentity.isEmpty())
		{
			return resultAdapter.missingExternalIdentity(
					configuration.identityMappingConfiguration().externalIdentityAttributeName());
		}

		final var revocationResult = authDeps.tokenRevocationVerifier()
		                                     .verify(TokenIssuance.of(externalIdentity.get(), issuedAt.get()));

		return switch (revocationResult)
		{
			case TokenRevocationVerificationSuccess _ -> exchange(authDeps, rawToken);
			case TokenRevocationVerificationFailure failure -> resultAdapter.currentnessFailure(failure);
		};
	}

	private AuthenticationResult exchange(
			final AuthenticationDependencies<ExternalIdentity, User> authDeps,
			final String rawToken)
	{
		// Step 3: Exchange upstream token for internal token → build identity
		final ExchangeResult exchangeResult = authDeps.tokenExchangeService().exchange(rawToken);
		return switch (exchangeResult)
		{
			case ExchangeSuccess success ->
					AuthenticationSuccess.of(ExchangeSuccessAuthenticatedIdentity.of(success.token()));
			case ExchangeFailure failure -> resultAdapter.exchangeFailure(failure);
		};
	}

	private List<Portent<AuthenticationResult>> exceptional()
	{
		return List.of(Portent.foretell(RuntimeException.class,
				exception -> resultAdapter.unavailable(exception.getMessage())));
	}

	private AuthenticationServiceImpl(final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
	                                  final AuthenticationResultAdapter resultAdapter,
	                                  final LazyAuthenticationDependencies<ExternalIdentity, User> dependencies)
	{
		this.configuration = configuration;
		this.resultAdapter = resultAdapter;
		this.dependencies = dependencies;
	}
}
