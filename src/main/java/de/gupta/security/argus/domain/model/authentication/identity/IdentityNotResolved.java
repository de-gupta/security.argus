package de.gupta.security.argus.domain.model.authentication.identity;

import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;

import java.util.Optional;

public record IdentityNotResolved(IdentityNotResolvedReason reason, Optional<FailureDetails> details)
		implements AuthenticationFailure
{
	public static IdentityNotResolved of(final IdentityNotResolvedReason reason)
	{
		return new IdentityNotResolved(reason, Optional.empty());
	}

	public static IdentityNotResolved of(final IdentityNotResolvedReason reason, final String details)
	{
		return new IdentityNotResolved(reason, Optional.of(FailureDetails.of(details)));
	}

	public static IdentityNotResolved of(final IdentityNotResolvedReason reason, final FailureDetails details)
	{
		return new IdentityNotResolved(reason, Optional.of(details));
	}

	@Override
	public String description()
	{
		return reason.description();
	}
}