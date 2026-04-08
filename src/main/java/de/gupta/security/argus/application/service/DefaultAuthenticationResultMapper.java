package de.gupta.security.argus.application.service;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailableReason;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolvedReason;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationFailureReason;

import java.util.Optional;

final class DefaultAuthenticationResultMapper implements AuthenticationResultMapper
{
	@Override
	public AuthenticationResult invalidCredential(final VerificationFailure failure)
	{
		return failure.details()
		              .map(details -> InvalidCredential.of(map(failure.reason()), details))
		              .orElseGet(() -> InvalidCredential.of(map(failure.reason())));
	}

	@Override
	public AuthenticationResult missingExternalIdentity(final String identityAttributeName)
	{
		return IdentityNotResolved.of(IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY, identityAttributeName);
	}

	@Override
	public AuthenticationResult userNotFound(final Object externalIdentity)
	{
		return IdentityNotResolved.of(IdentityNotResolvedReason.USER_NOT_FOUND, String.valueOf(externalIdentity));
	}

	@Override
	public AuthenticationResult missingLocalSubject()
	{
		return IdentityNotResolved.of(IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT);
	}

	@Override
	public AuthenticationResult exchangeFailure(final ExchangeFailure failure)
	{
		return unavailable(detailOf("exchange", failure.reason().name(), failure.details()));
	}

	@Override
	public AuthenticationResult internalCredentialFailure(final VerificationFailure failure)
	{
		return unavailable(detailOf("internal-token-verification", failure.reason().name(), failure.details()));
	}

	@Override
	public AuthenticationResult missingVersionClaim(final String versionClaimName)
	{
		return unavailable("Missing internal token version claim: " + versionClaimName);
	}

	@Override
	public AuthenticationResult subjectMismatch(final String expectedSubject, final String actualSubject)
	{
		return unavailable(
				"Internal token subject mismatch: expected=" + expectedSubject + ", actual=" + actualSubject);
	}

	@Override
	public AuthenticationResult currentnessFailure(final TokenVersionVerificationFailure<Long> failure)
	{
		return switch (failure.reason())
		{
			case VERSION_MISMATCH -> failure.details()
			                                .map(details -> AuthenticationNotCurrent.of(
													AuthenticationNotCurrentReason.VERSION_MISMATCH, details))
			                                .orElseGet(() -> AuthenticationNotCurrent.of(
													AuthenticationNotCurrentReason.VERSION_MISMATCH));
			case VERSION_LOOKUP_FAILED -> failure.details()
			                                     .map(details -> AuthenticationUnavailable.of(
														 AuthenticationUnavailableReason.IDENTITY_STATE_UNAVAILABLE,
														 details))
			                                     .orElseGet(() -> AuthenticationUnavailable.of(
														 AuthenticationUnavailableReason.IDENTITY_STATE_UNAVAILABLE));
		};
	}

	@Override
	public AuthenticationResult unavailable(final String details)
	{
		return AuthenticationUnavailable.of(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE, details);
	}

	private InvalidCredentialReason map(final VerificationFailureReason reason)
	{
		return switch (reason)
		{
			case MALFORMED -> InvalidCredentialReason.MALFORMED;
			case INVALID_SIGNATURE -> InvalidCredentialReason.INVALID_SIGNATURE;
			case EXPIRED -> InvalidCredentialReason.EXPIRED;
			case NOT_YET_VALID -> InvalidCredentialReason.NOT_YET_VALID;
			case MISSING_SUBJECT -> InvalidCredentialReason.MISSING_REQUIRED_CLAIM;
			case INVALID_ISSUER -> InvalidCredentialReason.INVALID_ISSUER;
			case INVALID_AUDIENCE -> InvalidCredentialReason.INVALID_AUDIENCE;
			case UNSUPPORTED -> InvalidCredentialReason.UNSUPPORTED;
		};
	}

	private String detailOf(final String phase,
	                        final String reason,
	                        final Optional<String> details)
	{
		return details.map(value -> phase + ":" + reason + ":" + value)
		              .orElseGet(() -> phase + ":" + reason);
	}
}