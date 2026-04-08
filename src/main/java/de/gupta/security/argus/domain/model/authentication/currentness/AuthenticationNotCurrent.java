package de.gupta.security.argus.domain.model.authentication.currentness;

import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;

import java.util.Objects;
import java.util.Optional;

public record AuthenticationNotCurrent(AuthenticationNotCurrentReason reason, Optional<String> details)
		implements AuthenticationFailure
{
	public static AuthenticationNotCurrent of(final AuthenticationNotCurrentReason reason)
	{
		return new AuthenticationNotCurrent(reason, Optional.empty());
	}

	public static AuthenticationNotCurrent of(final AuthenticationNotCurrentReason reason, final String details)
	{
		return new AuthenticationNotCurrent(reason, Optional.of(Objects.requireNonNull(details, "details must not be null")));
	}

	public AuthenticationNotCurrent
	{
		reason = Objects.requireNonNull(reason, "reason must not be null");
		details = Objects.requireNonNull(details, "details must not be null");
	}
}
