package de.gupta.security.argus.domain.model.authentication;

import java.util.Objects;
import java.util.Optional;

public record InvalidCredential(InvalidCredentialReason reason, Optional<String> details)
		implements AuthenticationFailure
{
	public static InvalidCredential of(final InvalidCredentialReason reason)
	{
		return new InvalidCredential(reason, Optional.empty());
	}

	public static InvalidCredential of(final InvalidCredentialReason reason, final String details)
	{
		return new InvalidCredential(reason, Optional.of(Objects.requireNonNull(details, "details must not be null")));
	}

	public InvalidCredential
	{
		reason = Objects.requireNonNull(reason, "reason must not be null");
		details = Objects.requireNonNull(details, "details must not be null");
	}
}
