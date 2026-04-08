package de.gupta.security.argus.api.identity;

import de.gupta.security.argus.utility.ValidationUtility;

import java.util.Objects;

public record IdentityMappingConfiguration<User>(String externalIdentityAttributeName,
                                                 UserResolver<String, User> userResolver,
                                                 LocalSubjectResolver<User> localSubjectResolver,
                                                 RoleResolver<User> roleResolver,
                                                 UserTokenVersionResolver<User> userTokenVersionResolver,
                                                 AttributeEnricher<User> attributeEnricher)
{
	public static <User> IdentityMappingConfiguration<User> of(
			final String externalIdentityAttributeName,
			final UserResolver<String, User> userResolver,
			final LocalSubjectResolver<User> localSubjectResolver,
			final RoleResolver<User> roleResolver,
			final UserTokenVersionResolver<User> userTokenVersionResolver,
			final AttributeEnricher<User> attributeEnricher)
	{
		return new IdentityMappingConfiguration<>(externalIdentityAttributeName,
				userResolver,
				localSubjectResolver,
				roleResolver,
				userTokenVersionResolver,
				attributeEnricher);
	}

	public static <User> IdentityMappingConfiguration<User> of(
			final UserResolver<String, User> userResolver,
			final LocalSubjectResolver<User> localSubjectResolver,
			final RoleResolver<User> roleResolver,
			final UserTokenVersionResolver<User> userTokenVersionResolver)
	{
		return of("sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				userTokenVersionResolver,
				AttributeEnricher.none());
	}

	public IdentityMappingConfiguration
	{
		externalIdentityAttributeName = ValidationUtility.requireNonBlank(externalIdentityAttributeName,
				"externalIdentityAttributeName must not be blank");
		userResolver = Objects.requireNonNull(userResolver, "userResolver must not be null");
		localSubjectResolver = Objects.requireNonNull(localSubjectResolver, "localSubjectResolver must not be null");
		roleResolver = Objects.requireNonNull(roleResolver, "roleResolver must not be null");
		userTokenVersionResolver = Objects.requireNonNull(userTokenVersionResolver,
				"userTokenVersionResolver must not be null");
		attributeEnricher = Objects.requireNonNull(attributeEnricher, "attributeEnricher must not be null");
	}
}