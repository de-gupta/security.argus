package de.gupta.security.argus.application.service;

import de.gupta.aletheia.trials.Fallible;
import de.gupta.aletheia.trials.Portent;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.identity.NormalizedTokenAuthenticatedIdentity;
import de.gupta.security.augustus.domain.model.Token;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailure;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationSuccess;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.hermes.domain.model.ExchangeSuccess;
import de.gupta.security.themis.domain.model.NormalizedToken;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationSuccess;

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
		return new AuthenticationServiceImpl<>(configuration,
				resultMapper,
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
		final AuthenticationDependencies authenticationDependencies = dependencies.summon();
		final ExchangeResult exchangeResult = authenticationDependencies.tokenExchangeService().exchange(token);
		return switch (exchangeResult)
		{
			case ExchangeSuccess success -> verify(authenticationDependencies, success.token().token());
			case ExchangeFailure failure -> resultAdapter.exchangeFailure(failure);
		};
	}

	private AuthenticationResult verify(final AuthenticationDependencies authenticationDependencies,
	                                    final String issuedToken)
	{
		final var verificationResult = authenticationDependencies.authenticatedTokenVerifier().verify(issuedToken);
		return switch (verificationResult)
		{
			case VerificationSuccess success -> checkVersion(authenticationDependencies, success.token());
			case VerificationFailure failure -> resultAdapter.internalCredentialFailure(failure);
		};
	}

	private AuthenticationResult checkVersion(
			final AuthenticationDependencies authenticationDependencies,
			final NormalizedToken verifiedToken)
	{
		final Optional<Long> versionOpt = resolveVersion(verifiedToken);
		if (versionOpt.isEmpty())
		{
			return resultAdapter.missingVersionClaim(configuration.authenticatedTokenContract().versionAttributeName());
		}
		final var currentnessResult = authenticationDependencies.tokenVersionVerifier()
		                                                        .verify(
																		new SubjectVersionToken(verifiedToken.subject(),
																				versionOpt.get()));
		return switch (currentnessResult)
		{
			case TokenVersionVerificationSuccess<Long> _ -> authenticateSuccess(verifiedToken);
			case TokenVersionVerificationFailure<Long> failure -> resultAdapter.currentnessFailure(failure);
		};
	}

	private List<Portent<AuthenticationResult>> exceptional()
	{
		return List.of(Portent.foretell(RuntimeException.class,
				exception -> resultAdapter.unavailable(exception.getMessage())));
	}

	private AuthenticationResult authenticateSuccess(final NormalizedToken token)
	{
		return AuthenticationSuccess.of(NormalizedTokenAuthenticatedIdentity.of(token));
	}

	private Optional<Long> resolveVersion(final NormalizedToken token)
	{
		return token.version().map(Number::longValue);
	}

	private AuthenticationServiceImpl(final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
	                                  final AuthenticationResultAdapter resultAdapter,
	                                  final LazyAuthenticationDependencies<ExternalIdentity, User> dependencies)
	{
		this.configuration = configuration;
		this.resultAdapter = resultAdapter;
		this.dependencies = dependencies;
	}

	private record SubjectVersionToken(String user, Long version) implements Token<String, Long>
	{
	}
}