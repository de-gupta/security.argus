package de.gupta.security.argus.application.service;

import de.gupta.aletheia.functional.Unfolding;
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
import java.util.SequencedMap;
import java.util.function.Function;
import java.util.function.Predicate;

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

	private SequencedMap<Predicate<? super ExchangeResult>, Function<? super ExchangeResult, AuthenticationResult>> authenticationPipelineMap()
	{
		Predicate<? super ExchangeResult> exchangeSuccess = ExchangeSuccess.class::isInstance;
		Predicate<? super ExchangeResult> exchangeFailure = ExchangeFailure.class::isInstance;
		Function<? super ExchangeResult, AuthenticationResult> successBranch =
				exchangeResult -> verify(dependencies.summon(), ((ExchangeSuccess) exchangeResult).token().token());
		Function<? super ExchangeResult, AuthenticationResult> failureBranch =
				exchangeResult -> resultAdapter.exchangeFailure(((ExchangeFailure) exchangeResult));

//		return SequencedMap.of(exchangeSuccess, successBranch, exchangeFailure, failureBranch);
		return null;
	}

	private AuthenticationResult authenticatePipeline(final String token)
	{
		final AuthenticationDependencies authenticationDependencies = dependencies.summon();
//		return Unfolding.beckon(dependencies)
//		                .metamorphose(LazyAuthenticationDependencies::summon)
//		                .metamorphose(dependencies -> dependencies.tokenExchangeService().exchange(token))
//		                .cleave(authenticationPipelineMap(), AuthenticationUnavailable.of(null));

		return Unfolding.beckon(authenticationDependencies.tokenExchangeService().exchange(token))
		                .cleave(exchangeResult -> switch (exchangeResult)
						{
							case ExchangeSuccess _ -> true;
							case ExchangeFailure _ -> false;
						}, exchangeResult -> switch (exchangeResult)
						{
							case ExchangeSuccess success -> verify(authenticationDependencies, success.token().token());
							case ExchangeFailure _ -> throw impossible("exchange success", exchangeResult);
						}, exchangeResult -> switch (exchangeResult)
						{
							case ExchangeFailure failure -> resultAdapter.exchangeFailure(failure);
							case ExchangeSuccess _ -> throw impossible("exchange failure", exchangeResult);
						})
		                .summon();
	}

	private AuthenticationResult verify(final AuthenticationDependencies authenticationDependencies,
	                                    final String issuedToken)
	{
		return Unfolding.beckon(authenticationDependencies.authenticatedTokenVerifier().verify(issuedToken))
		                .cleave(verificationResult -> switch (verificationResult)
						{
							case VerificationSuccess _ -> true;
							case VerificationFailure _ -> false;
						}, verificationResult -> switch (verificationResult)
						{
							case VerificationSuccess success ->
									checkVersion(authenticationDependencies, success.token());
							case VerificationFailure _ -> throw impossible("verification success", verificationResult);
						}, verificationResult -> switch (verificationResult)
						{
							case VerificationFailure failure -> resultAdapter.internalCredentialFailure(failure);
							case VerificationSuccess _ -> throw impossible("verification failure", verificationResult);
						})
		                .summon();
	}

	private AuthenticationResult checkVersion(
			final AuthenticationDependencies authenticationDependencies,
			final NormalizedToken verifiedToken)
	{
		return Unfolding.augur(resolveVersion(verifiedToken))
		                .metamorphose(version -> new SubjectVersionToken(verifiedToken.subject(), version))
		                .metamorphose(authenticationDependencies.tokenVersionVerifier()::verifyResult)
		                .cleave(currentnessResult -> switch (currentnessResult)
						{
							case TokenVersionVerificationSuccess<Long> _ -> true;
							case TokenVersionVerificationFailure<Long> _ -> false;
						}, currentnessResult -> switch (currentnessResult)
						{
							case TokenVersionVerificationSuccess<Long> _ -> authenticateSuccess(verifiedToken);
							case TokenVersionVerificationFailure<Long> _ ->
									throw impossible("currentness success", currentnessResult);
						}, currentnessResult -> switch (currentnessResult)
						{
							case TokenVersionVerificationFailure<Long> failure ->
									resultAdapter.currentnessFailure(failure);
							case TokenVersionVerificationSuccess<Long> _ ->
									throw impossible("currentness failure", currentnessResult);
						})
		                .ordain(() -> resultAdapter.missingVersionClaim(
								configuration.authenticatedTokenContract().versionAttributeName()));
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

	private IllegalStateException impossible(final String expected, final Object actual)
	{
		return new IllegalStateException("Expected " + expected + " but got " + actual.getClass().getSimpleName());
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