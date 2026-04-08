package de.gupta.security.argus.domain.model.authentication.credential;

import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;

import java.util.Optional;

public record InvalidCredential(InvalidCredentialReason reason, Optional<FailureDetails> details)
		implements AuthenticationFailure
{
	public static InvalidCredential of(final InvalidCredentialReason reason)
	{
		return new InvalidCredential(reason, Optional.empty());
	}

	public static InvalidCredential of(final InvalidCredentialReason reason, final String details)
	{
		return new InvalidCredential(reason, Optional.of(FailureDetails.of(details)));
	}

	public static InvalidCredential of(final InvalidCredentialReason reason, final FailureDetails details)
	{
		return new InvalidCredential(reason, Optional.of(details));
	}
}