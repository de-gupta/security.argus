package de.gupta.security.argus.utility;

import de.gupta.aletheia.functional.Unfolding;

public final class ValidationUtility
{
	public static String requireNonBlank(final String value, final String message)
	{
		return Unfolding.beckon(value)
		                .discern(candidate -> candidate != null && !candidate.isBlank(),
				                () -> new IllegalArgumentException(message))
		                .summon();
	}

	private ValidationUtility()
	{
	}
}
