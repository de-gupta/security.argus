package de.gupta.security.argus.api.identity;

import de.gupta.security.argus.utility.ValidationUtility;

import java.util.Objects;

public record IdentityMappingConfiguration<ExternalIdentity, User>(String externalIdentityAttributeName,
                                                                   ExternalIdentityAdapter<ExternalIdentity> externalIdentityAdapter,
                                                                   UserResolver<ExternalIdentity, User> userResolver,
                                                                   LocalSubjectResolver<User> localSubjectResolver,
                                                                   RoleResolver<User> roleResolver,
                                                                   UserRevocationResolver<User> userRevocationResolver)
{
    public static <ExternalIdentity, User> IdentityMappingConfiguration<ExternalIdentity, User> of(
            final String externalIdentityAttributeName,
            final ExternalIdentityAdapter<ExternalIdentity> externalIdentityAdapter,
            final UserResolver<ExternalIdentity, User> userResolver,
            final LocalSubjectResolver<User> localSubjectResolver,
            final RoleResolver<User> roleResolver,
            final UserRevocationResolver<User> userRevocationResolver)
    {
        return new IdentityMappingConfiguration<>(externalIdentityAttributeName,
                externalIdentityAdapter,
                userResolver,
                localSubjectResolver,
                roleResolver,
				userRevocationResolver);
    }

    public static <ExternalIdentity, User> IdentityMappingConfiguration<ExternalIdentity, User> of(
            final ExternalIdentityAdapter<ExternalIdentity> externalIdentityAdapter,
            final UserResolver<ExternalIdentity, User> userResolver,
            final LocalSubjectResolver<User> localSubjectResolver,
            final RoleResolver<User> roleResolver,
            final UserRevocationResolver<User> userRevocationResolver)
    {
        return of("sub",
                externalIdentityAdapter,
                userResolver,
                localSubjectResolver,
                roleResolver,
				userRevocationResolver);
    }

    public IdentityMappingConfiguration
    {
        externalIdentityAttributeName = ValidationUtility.requireNonBlank(externalIdentityAttributeName,
                "externalIdentityAttributeName must not be blank");
        externalIdentityAdapter = Objects.requireNonNull(externalIdentityAdapter,
                "externalIdentityAdapter must not be null");
        userResolver = Objects.requireNonNull(userResolver, "userResolver must not be null");
        localSubjectResolver = Objects.requireNonNull(localSubjectResolver, "localSubjectResolver must not be null");
        roleResolver = Objects.requireNonNull(roleResolver, "roleResolver must not be null");
		userRevocationResolver = Objects.requireNonNull(userRevocationResolver,
				"userRevocationResolver must not be null");
    }
}