package de.gupta.security.argus.domain.model.authentication.availability;

import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;

import java.util.Objects;
import java.util.Optional;

public record AuthenticationUnavailable(AuthenticationUnavailableReason reason, Optional<FailureDetails> details)
		implements AuthenticationFailure
{
	public static AuthenticationUnavailable of(final AuthenticationUnavailableReason reason)
	{
		return new AuthenticationUnavailable(reason, Optional.empty());
	}

	public static AuthenticationUnavailable of(final AuthenticationUnavailableReason reason, final String details)
	{
		return new AuthenticationUnavailable(reason, Optional.of(FailureDetails.of(details)));
	}

	public static AuthenticationUnavailable of(final AuthenticationUnavailableReason reason,
	                                           final FailureDetails details)
	{
		return new AuthenticationUnavailable(reason, Optional.of(details));
	}
}