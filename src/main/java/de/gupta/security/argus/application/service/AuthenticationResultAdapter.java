package de.gupta.security.argus.application.service;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.themis.domain.model.VerificationFailure;

public interface AuthenticationResultAdapter
{
	AuthenticationResult invalidCredential(final VerificationFailure failure);

	AuthenticationResult missingExternalIdentity(final String identityAttributeName);

	AuthenticationResult userNotFound(final Object externalIdentity);

	AuthenticationResult missingLocalSubject();

	AuthenticationResult exchangeFailure(final ExchangeFailure failure);

	AuthenticationResult internalCredentialFailure(final VerificationFailure failure);

	AuthenticationResult missingVersionClaim(final String versionClaimName);

	AuthenticationResult currentnessFailure(final TokenVersionVerificationFailure<Long> failure);

	AuthenticationResult unavailable(final String details);
}