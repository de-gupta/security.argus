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
import de.gupta.security.augustus.domain.model.TokenRevocationVerificationFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationFailureReason;

import java.util.Optional;

final class DefaultAuthenticationResultAdapter implements AuthenticationResultAdapter
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
		return switch (failure.reason())
		{
			case UPSTREAM_VERIFICATION_FAILED -> invalidCredentialFromHermes(failure.details());
			case MISSING_EXTERNAL_IDENTITY -> failure.details()
			                                         .map(this::missingExternalIdentity)
			                                         .orElseGet(() -> IdentityNotResolved.of(
					                                         IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY));
			case USER_NOT_FOUND -> failure.details()
			                              .map(this::userNotFound)
			                              .orElseGet(() -> IdentityNotResolved.of(
					                              IdentityNotResolvedReason.USER_NOT_FOUND));
			case MISSING_LOCAL_SUBJECT -> IdentityNotResolved.of(IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT);
			case ISSUANCE_FAILED -> unavailable(detailOf("exchange", failure.reason().name(), failure.details()));
		};
	}

	@Override
	public AuthenticationResult missingIssuedAt()
	{
		return InvalidCredential.of(InvalidCredentialReason.MISSING_REQUIRED_CLAIM,
				"The upstream token is missing the iat claim required for revocation checking.");
	}

	@Override
	public AuthenticationResult currentnessFailure(final TokenRevocationVerificationFailure failure)
	{
		return switch (failure.reason())
		{
			case TOKEN_SUPERSEDED -> failure.details()
			                                .map(details -> AuthenticationNotCurrent.of(
													AuthenticationNotCurrentReason.REVOKED, details))
			                                .orElseGet(() -> AuthenticationNotCurrent.of(
													AuthenticationNotCurrentReason.REVOKED));
			case USER_NOT_FOUND -> failure.details()
			                              .map(this::userNotFound)
			                              .orElseGet(() -> IdentityNotResolved.of(
												  IdentityNotResolvedReason.USER_NOT_FOUND));
			case REVOCATION_STATE_UNAVAILABLE -> failure.details()
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

	private AuthenticationResult invalidCredentialFromHermes(final Optional<String> details)
	{
		final Optional<VerificationFailureReason> upstreamReason =
				details.flatMap(this::parseVerificationFailureReason);
		return upstreamReason.map(reason -> invalidCredential(VerificationFailure.of(reason)))
		                     .orElseGet(() -> InvalidCredential.of(InvalidCredentialReason.UNSUPPORTED));
	}

	private Optional<VerificationFailureReason> parseVerificationFailureReason(final String details)
	{
		try
		{
			return Optional.of(VerificationFailureReason.valueOf(details));
		}
		catch (IllegalArgumentException ignored)
		{
			return Optional.empty();
		}
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

	private String detailOf(final String phase, final String reason, final Optional<String> details)
	{
		return details.map(value -> phase + ":" + reason + ":" + value)
		              .orElseGet(() -> phase + ":" + reason);
	}
}