package de.gupta.security.argus.application.service;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.aletheia.trials.Fallible;
import de.gupta.aletheia.trials.Portent;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.identity.NormalizedTokenAuthenticatedIdentity;
import de.gupta.security.augustus.domain.model.Token;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailure;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationResult;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.hermes.domain.model.ExchangeSuccess;
import de.gupta.security.themis.domain.model.NormalizedToken;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationResult;
import de.gupta.security.themis.domain.model.VerificationSuccess;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

final class AuthenticationServiceImpl<ExternalIdentity, User> implements AuthenticationService
{
	private final AuthenticatorConfiguration<ExternalIdentity, User> configuration;
	private final AuthenticationResultMapper resultMapper;
	private final LazyAuthenticationDependencies<ExternalIdentity, User> dependencies;

	static <ExternalIdentity, User> AuthenticationService create(
			final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
			final AuthenticationResultMapper resultMapper)
	{
		return new AuthenticationServiceImpl<>(configuration,
				resultMapper,
				LazyAuthenticationDependencies.create(configuration));
	}

	@Override
	public AuthenticationResult authenticate(final String token)
	{
		return Fallible.beckon(token)
		               .metamorphose(this::authenticateUnchecked, exceptional())
		               .coronate(Function.identity(), exception -> resultMapper.unavailable(exception.getMessage()));
	}

	private AuthenticationResult authenticateUnchecked(final String token)
	{
		final VerificationResult verificationResult = dependencies.summon().upstreamTokenVerifier().verify(token);
		return verificationResult instanceof VerificationFailure failure
				? resultMapper.invalidCredential(failure)
				: authenticateTrustedUpstreamToken(token, ((VerificationSuccess) verificationResult).token());
	}

	private AuthenticationResult authenticateTrustedUpstreamToken(final String rawToken,
	                                                              final NormalizedToken upstreamToken)
	{
		return Unfolding.augur(resolveExternalIdentity(upstreamToken))
		                .metamorphose(externalIdentity ->
								new ExternalIdentityContext<>(rawToken, upstreamToken, externalIdentity))
		                .metamorphose(this::authenticateWithExternalIdentity)
		                .rescue(resultMapper.missingExternalIdentity(
								configuration.identityMappingConfiguration().externalIdentityAttributeName()));
	}

	private AuthenticationResult authenticateWithExternalIdentity(
			final ExternalIdentityContext<ExternalIdentity> externalIdentityContext)
	{
		return Unfolding.augur(resolveUser(externalIdentityContext.externalIdentity()))
		                .metamorphose(user -> new LocalUserContext<>(externalIdentityContext.rawToken(),
								externalIdentityContext.upstreamToken(),
								externalIdentityContext.externalIdentity(),
								user))
		                .metamorphose(this::authenticateWithLocalUser)
		                .rescue(resultMapper.userNotFound(externalIdentityContext.externalIdentity()));
	}

	private AuthenticationResult authenticateWithLocalUser(
			final LocalUserContext<ExternalIdentity, User> localUserContext)
	{
		return Unfolding.augur(resolveLocalSubject(localUserContext.user()))
		                .metamorphose(localSubject -> new LocalSubjectContext<>(localUserContext.rawToken(),
								localUserContext.upstreamToken(),
								localUserContext.externalIdentity(),
								localUserContext.user(),
								localSubject))
		                .metamorphose(this::exchangeAndAuthenticateInternalToken)
		                .rescue(resultMapper.missingLocalSubject());
	}

	private AuthenticationResult exchangeAndAuthenticateInternalToken(
			final LocalSubjectContext<ExternalIdentity, User> localSubjectContext)
	{
		final ExchangeResult exchangeResult =
				dependencies.summon().tokenExchangeService().exchange(localSubjectContext.rawToken());
		return exchangeResult instanceof ExchangeFailure failure
				? resultMapper.exchangeFailure(failure)
				: authenticateIssuedToken(((ExchangeSuccess) exchangeResult).token().token(),
				localSubjectContext.user(),
				localSubjectContext.localSubject());
	}

	private AuthenticationResult authenticateIssuedToken(final String issuedToken,
	                                                     final User user,
	                                                     final String expectedLocalSubject)
	{
		final VerificationResult verificationResult =
				dependencies.summon().authenticatedTokenVerifier().verify(issuedToken);
		return verificationResult instanceof VerificationFailure failure
				? resultMapper.internalCredentialFailure(failure)
				: authenticateVerifiedInternalToken(((VerificationSuccess) verificationResult).token(),
				user,
				expectedLocalSubject);
	}

	private AuthenticationResult authenticateVerifiedInternalToken(final NormalizedToken token,
	                                                               final User user,
	                                                               final String expectedLocalSubject)
	{
		if (!expectedLocalSubject.equals(token.subject()))
		{
			return resultMapper.subjectMismatch(expectedLocalSubject, token.subject());
		}

		return resolveVersion(token)
				.<AuthenticationResult>map(version -> verifyCurrentness(token, user, version))
				.orElseGet(() -> resultMapper.missingVersionClaim(
						configuration.authenticatedTokenContract().versionAttributeName()));
	}

	private AuthenticationResult verifyCurrentness(final NormalizedToken token, final User user, final long version)
	{
		final TokenVersionVerificationResult<Long> currentnessResult = dependencies.summon()
		                                                                           .tokenVersionVerifier()
		                                                                           .verifyResult(
																						   new UserVersionToken<>(user,
																								   version));
		return currentnessResult instanceof TokenVersionVerificationFailure<Long> failure
				? resultMapper.currentnessFailure(failure)
				: authenticateSuccess(token);
	}

	private AuthenticationResult authenticateSuccess(final NormalizedToken token)
	{
		return AuthenticationSuccess.of(NormalizedTokenAuthenticatedIdentity.of(token,
				configuration.authenticatedTokenContract().roleAttributeName()));
	}

	private Optional<ExternalIdentity> resolveExternalIdentity(final NormalizedToken upstreamToken)
	{
		return rawExternalIdentity(upstreamToken).map(this::castExternalIdentity);
	}

	private Optional<String> rawExternalIdentity(final NormalizedToken upstreamToken)
	{
		return "sub".equals(configuration.identityMappingConfiguration().externalIdentityAttributeName())
				? Optional.ofNullable(upstreamToken.subject()).filter(StringSanitizationUtility::isNotBlank)
				:
				upstreamToken.stringClaim(configuration.identityMappingConfiguration().externalIdentityAttributeName());
	}

	private Optional<User> resolveUser(final ExternalIdentity externalIdentity)
	{
		return configuration.identityMappingConfiguration().userResolver().resolveUser(externalIdentity);
	}

	private Optional<String> resolveLocalSubject(final User user)
	{
		return Optional.ofNullable(
							   configuration.identityMappingConfiguration().localSubjectResolver().resolveSubject(user))
		               .filter(StringSanitizationUtility::isNotBlank);
	}

	private Optional<Long> resolveVersion(final NormalizedToken token)
	{
		return token.longClaim(configuration.authenticatedTokenContract().versionAttributeName());
	}

	@SuppressWarnings("unchecked")
	private ExternalIdentity castExternalIdentity(final String externalIdentity)
	{
		return (ExternalIdentity) externalIdentity;
	}

	private List<Portent<AuthenticationResult>> exceptional()
	{
		return List.of(Portent.foretell(RuntimeException.class,
				exception -> resultMapper.unavailable(exception.getMessage())));
	}

	private AuthenticationServiceImpl(final AuthenticatorConfiguration<ExternalIdentity, User> configuration,
	                                  final AuthenticationResultMapper resultMapper,
	                                  final LazyAuthenticationDependencies<ExternalIdentity, User> dependencies)
	{
		this.configuration = configuration;
		this.resultMapper = resultMapper;
		this.dependencies = dependencies;
	}

	private record ExternalIdentityContext<T>(String rawToken, NormalizedToken upstreamToken, T externalIdentity)
	{
	}

	private record LocalUserContext<E, U>(String rawToken, NormalizedToken upstreamToken, E externalIdentity, U user)
	{
	}

	private record LocalSubjectContext<E, U>(String rawToken,
	                                         NormalizedToken upstreamToken,
	                                         E externalIdentity,
	                                         U user,
	                                         String localSubject)
	{
	}

	private record UserVersionToken<U>(U user, Long version) implements Token<U, Long>
	{
	}
}