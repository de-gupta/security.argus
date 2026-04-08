package de.gupta.security.argus.domain.model;

import java.util.Objects;
import java.util.Optional;

public record IdentityNotResolved(IdentityNotResolvedReason reason, Optional<String> details)
		implements AuthenticationFailure
{
	public static IdentityNotResolved of(final IdentityNotResolvedReason reason)
	{
		return new IdentityNotResolved(reason, Optional.empty());
	}

	public static IdentityNotResolved of(final IdentityNotResolvedReason reason, final String details)
	{
		return new IdentityNotResolved(reason, Optional.of(Objects.requireNonNull(details, "details must not be null")));
	}

	public IdentityNotResolved
	{
		reason = Objects.requireNonNull(reason, "reason must not be null");
		details = Objects.requireNonNull(details, "details must not be null");
	}
}
