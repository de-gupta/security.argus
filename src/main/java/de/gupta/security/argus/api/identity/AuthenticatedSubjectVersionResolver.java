package de.gupta.security.argus.api.identity;

@FunctionalInterface
public interface AuthenticatedSubjectVersionResolver
{
	long resolveVersion(final String subject);
}