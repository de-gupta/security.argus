package de.gupta.security.argus.api.identity;

@FunctionalInterface
public interface LocalSubjectResolver<User>
{
	String resolveSubject(final User user);
}
