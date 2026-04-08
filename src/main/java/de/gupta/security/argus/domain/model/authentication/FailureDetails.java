package de.gupta.security.argus.domain.model.authentication;

public record FailureDetails(String message)
{
	public static FailureDetails of(final String message)
	{
		return new FailureDetails(message);
	}
}