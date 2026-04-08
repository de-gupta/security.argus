package de.gupta.security.argus.api;

@FunctionalInterface
public interface UserTokenVersionResolver<User>
{
	long resolveVersion(final User user);
}