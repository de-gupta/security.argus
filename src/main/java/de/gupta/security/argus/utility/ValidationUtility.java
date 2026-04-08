package de.gupta.security.argus.utility;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;

public final class ValidationUtility
{
	public static String requireNonBlank(final String value, final String message)
	{
		return Unfolding.beckon(value)
		                .discern(StringSanitizationUtility::isNotBlank)
		                .decree(() -> new IllegalArgumentException(message));
	}

	private ValidationUtility()
	{
	}
}