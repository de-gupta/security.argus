package de.gupta.security.argus.api;

@FunctionalInterface
public interface LocalSubjectResolver<User>
{
	String resolveSubject(final User user);
}
