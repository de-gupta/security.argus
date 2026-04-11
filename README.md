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
- `notBefore()`
- `roles()`

This is the trusted internal authentication view after the full Argus pipeline has passed.

## Usage

```java
import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.cache.AuthenticationCacheConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
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

## Caching

Argus supports optional result caching to avoid running the full pipeline on every request.
Caching is opt-in and disabled by default.

Results are keyed by a SHA-256 hash of the raw token string — the token is never stored in memory.

- `AuthenticationSuccess` entries are cached until the earlier of: the configured TTL or the token's own expiry
- All other failures are cached for a short configurable TTL to throttle replay of bad tokens
- `AuthenticationNotCurrent` is never cached — a version bump must take effect immediately

### Using the Caffeine-backed cache

```java
TokenAuthenticationCache cache = AuthenticationCacheConfiguration.withDefaults().build();

AuthenticatorConfiguration<String, LocalUser> configuration =
		AuthenticatorConfiguration.<String, LocalUser>builder()
		                          // ... other configuration ...
		                          .tokenAuthenticationCache(cache)
		                          .build();
```

### Custom TTL configuration

```java
TokenAuthenticationCache cache = AuthenticationCacheConfiguration.of(
		5_000L,              // maximum entries
		Duration.ofMinutes(2),   // success TTL
		Duration.ofSeconds(15)   // failure TTL
).build();
```

### Forcing invalidation

If a subject's version is bumped out-of-band (e.g., an admin revokes a session), any cached
success for that subject can be removed immediately:

```java
cache.invalidateBySubject(subject);
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

- you only need raw JWT verification — use `themis`
- you only need token issuance/exchange — use `hermes`
- you only need currentness/version checking — use `augustus`

## Relation To The Rest Of The Stack

- `themis`: trust the token
- `hermes`: mint the token
- `augustus`: confirm the token is still current
- `argus`: orchestrate the whole authentication pipeline