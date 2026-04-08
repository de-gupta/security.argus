package de.gupta.security.argus.api.identity;

@FunctionalInterface
public interface UserTokenVersionResolver<User>
{
	long resolveVersion(final User user);
}