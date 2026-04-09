package de.gupta.security.argus.domain.model.authentication.currentness;

import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;

import java.util.Optional;

public record AuthenticationNotCurrent(AuthenticationNotCurrentReason reason, Optional<FailureDetails> details)
		implements AuthenticationFailure
{
	public static AuthenticationNotCurrent of(final AuthenticationNotCurrentReason reason)
	{
		return new AuthenticationNotCurrent(reason, Optional.empty());
	}

	public static AuthenticationNotCurrent of(final AuthenticationNotCurrentReason reason, final String details)
	{
		return new AuthenticationNotCurrent(reason, Optional.of(FailureDetails.of(details)));
	}

	public static AuthenticationNotCurrent of(final AuthenticationNotCurrentReason reason, final FailureDetails details)
	{
		return new AuthenticationNotCurrent(reason, Optional.of(details));
	}

	@Override
	public String description()
	{
		return reason.description();
	}
}