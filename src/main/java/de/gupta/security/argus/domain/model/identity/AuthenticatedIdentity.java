package de.gupta.security.argus.domain.model.identity;

import java.util.Set;

public interface AuthenticatedIdentity extends IdentityAttributes
{
	Set<String> roles();
}