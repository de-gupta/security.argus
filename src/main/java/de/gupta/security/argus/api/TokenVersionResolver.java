package de.gupta.security.argus.api;

@FunctionalInterface
public interface TokenVersionResolver<User>
{
	long resolveVersion(final User user);
}
