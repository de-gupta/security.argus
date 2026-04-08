package de.gupta.security.argus.api.identity;

import java.util.Set;

@FunctionalInterface
public interface RoleResolver<User>
{
	Set<String> resolveRoles(final User user);
}
