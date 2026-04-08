package de.gupta.security.argus.domain.model.authentication.availability;

import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;

import java.util.Objects;
import java.util.Optional;

public record AuthenticationUnavailable(AuthenticationUnavailableReason reason, Optional<String> details)
		implements AuthenticationFailure
{
	public static AuthenticationUnavailable of(final AuthenticationUnavailableReason reason)
	{
		return new AuthenticationUnavailable(reason, Optional.empty());
	}

	public static AuthenticationUnavailable of(final AuthenticationUnavailableReason reason, final String details)
	{
		return new AuthenticationUnavailable(reason, Optional.of(Objects.requireNonNull(details, "details must not be null")));
	}

	public AuthenticationUnavailable
	{
		reason = Objects.requireNonNull(reason, "reason must not be null");
		details = Objects.requireNonNull(details, "details must not be null");
	}
}
