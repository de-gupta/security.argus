# security.argus

`security.argus` is the convenience orchestrator over the rest of the stack.

It exists for consumers who do not want to wire `themis`, `hermes`, and `augustus` themselves.

Argus accepts one raw upstream token, runs the full authentication pipeline, and returns one typed result.

## What Argus Does

Argus performs this flow:

1. `hermes` exchanges the raw upstream token into an internal token
2. `themis` verifies the internal token cryptographically
3. `augustus` checks whether the authenticated subject is still current
4. Argus returns either:
    - `AuthenticationSuccess`
    - or one typed failure result

Argus does not expose sibling library APIs to consumers.

## What Consumers Provide

Consumers configure Argus with:

- how to trust the upstream issuer
- how to mint internal tokens
- how to verify the internally minted token
- how to resolve an upstream identity into a local user
- how to resolve a local subject
- how to resolve roles
- how to resolve a version for minting
- how to resolve current version by authenticated subject

The important consumer-owned seams are in `IdentityMappingConfiguration`:

- `ExternalIdentityAdapter<ExternalIdentity>`
- `UserResolver<ExternalIdentity, User>`
- `LocalSubjectResolver<User>`
- `RoleResolver<User>`
- `UserTokenVersionResolver<User>`
- `AuthenticatedSubjectVersionResolver`

That means:

- your `User` model stays yours
- your identity lookup stays yours
- your currentness/version state stays yours

## What Consumers Get Back

Consumers call one method:

```java
AuthenticationResult result = authenticator.authenticate(rawToken);
```

They receive one of:

- `AuthenticationSuccess`
- `InvalidCredential`
- `IdentityNotResolved`
- `AuthenticationNotCurrent`
- `AuthenticationUnavailable`

On success, consumers get an `AuthenticatedIdentity` with explicit normalized properties:

- `subject()`
- `issuer()`
- `audiences()`
- `issuedAt()`
- `expiresAt()`
- `validFrom()`
- `roles()`

This is the trusted internal authentication view after the full Argus pipeline has passed.

## Usage

```java
import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

record LocalUser(String id, String subject, long version)
{
}

AuthenticatorConfiguration<String, LocalUser> configuration =
		AuthenticatorConfiguration.<String, LocalUser>builder()
		                          .upstreamTrustConfiguration(UpstreamTrustConfiguration.Hmac.of(
										  TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"),
						                          Optional.of("supabase")),
										  "upstream-secret-value"))
		                          .authenticatedTokenContract(AuthenticatedTokenContract.of(
										  "argus",
										  Set.of("inventory"),
										  Duration.ofMinutes(15)))
		                          .authenticatedTokenMintingConfiguration(
										  AuthenticatedTokenMintingConfiguration.of(
												  TokenSignerConfiguration.Hmac.of("internal-secret-value")))
		                          .authenticatedTokenVerificationConfiguration(
										  AuthenticatedTokenVerificationConfiguration.of(
												  TokenTrustPolicy.of(Duration.ZERO, true, Set.of("inventory"),
								                          Optional.of("argus"))))
		                          .identityMappingConfiguration(IdentityMappingConfiguration.of(
										  ExternalIdentityAdapter.stringIdentity(),
										  externalIdentity -> findUserByExternalIdentity(externalIdentity),
										  LocalUser::subject,
										  user -> Set.of("ROLE_USER"),
										  LocalUser::version,
										  subject -> findCurrentVersionBySubject(subject)))
		                          .clock(Clock.systemUTC())
		                          .build();

Authenticator authenticator = AuthenticatorFactory.create(configuration);

AuthenticationResult result = authenticator.authenticate(rawToken);

if(result instanceof
AuthenticationSuccess success)
		{
String subject = success.identity().subject();
Set<String> roles = success.identity().roles();
}
```

## Reading The Example

In the example above, the consumer provides:

- upstream token trust settings
- internal token minting and verification settings
- external identity adaptation
- local user lookup
- subject mapping
- role resolution
- version-at-mint lookup
- current-version-by-subject lookup

Argus then returns a fully authenticated internal identity or a typed failure.

## When To Use Argus

Use Argus when:

- you already receive a token from an upstream identity provider
- you want a local internal token contract
- you want currentness/version checks after minting
- you want one framework-agnostic authentication entrypoint

Do not use Argus when:

- you only need raw JWT verification
  then use `themis`
- you only need token issuance/exchange
  then use `hermes`
- you only need currentness/version checking
  then use `augustus`

## Relation To The Rest Of The Stack

- `themis`: trust the token
- `hermes`: mint the token
- `augustus`: confirm the token is still current
- `argus`: orchestrate the whole authentication pipeline