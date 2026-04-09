package de.gupta.security.argus.application.service;

import de.gupta.aletheia.trials.Fallible;
import de.gupta.aletheia.trials.Portent;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.identity.NormalizedTokenAuthenticatedIdentity;
import de.gupta.security.augustus.domain.model.Token;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailure;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationResult;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationSuccess;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
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
                       .metamorphose(this::authenticateUnchecked, exceptional())
                       .coronate(Function.identity(), exception -> resultAdapter.unavailable(exception.getMessage()));
    }

    private AuthenticationResult authenticateUnchecked(final String token)
    {
        return switch (dependencies.summon().tokenExchangeService().exchange(token))
        {
            case ExchangeFailure failure -> resultAdapter.exchangeFailure(failure);
            case ExchangeSuccess success -> authenticateIssuedToken(success.token().token());
        };
    }

    private List<Portent<AuthenticationResult>> exceptional()
    {
        return List.of(Portent.foretell(RuntimeException.class,
                exception -> resultAdapter.unavailable(exception.getMessage())));
    }

    private AuthenticationResult authenticateIssuedToken(final String issuedToken)
    {
        return switch (dependencies.summon().authenticatedTokenVerifier().verify(issuedToken))
        {
            case VerificationFailure failure -> resultAdapter.internalCredentialFailure(failure);
            case VerificationSuccess success -> authenticateVerifiedInternalToken(success.token());
        };
    }

    private AuthenticationResult authenticateVerifiedInternalToken(final NormalizedToken token)
    {
        return resolveVersion(token)
                .map(version -> verifyCurrentness(token, version))
                .orElseGet(() -> resultAdapter.missingVersionClaim(
                        configuration.authenticatedTokenContract().versionAttributeName()));
    }

    private AuthenticationResult verifyCurrentness(final NormalizedToken token, final long version)
    {
        final TokenVersionVerificationResult<Long> currentnessResult = dependencies.summon()
                                                                                   .tokenVersionVerifier()
                                                                                   .verifyResult(
                                                                                           new SubjectVersionToken(
                                                                                                   token.subject(),
                                                                                                   version));
        return switch (currentnessResult)
        {
            case TokenVersionVerificationFailure<Long> failure -> resultAdapter.currentnessFailure(failure);
            case TokenVersionVerificationSuccess<Long> _ -> authenticateSuccess(token);
        };
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