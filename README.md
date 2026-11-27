# Ed25519 Signing Integration Examples

The same Ed25519 signing and verification flow, implemented in C#, Go, Java, Node.js and PHP. All five examples share the same API, environment variables, response format and error handling, so you can pick the one in your language and use it as a reference, or compare how each language does it.

| Directory | Language / framework |
|---|---|
| [csharp-ed25519-example](csharp-ed25519-example) | C# / ASP.NET Core (.NET 10), BouncyCastle |
| [go-ed25519-example](go-ed25519-example) | Go 1.27, standard library |
| [java-ed25519-example](java-ed25519-example) | Java 25 / Spring Boot 4, BouncyCastle |
| [node-ed25519-example](node-ed25519-example) | Node.js 24.22+ or 26+ / Express 5, `node:crypto` |
| [php-ed25519-example](php-ed25519-example) | PHP 8.5 / Slim 4, sodium, APCu |
| [testdata](testdata) | Test cases shared by all five examples |

## API

Both endpoints read the raw request body (any Content-Type is accepted), up to 8 MiB (8,388,608 bytes).

### `POST /Auth/sign` 

Signs the body with the operator's private key.

```json
{"key_id":"...","operator_id":"...","payload":"{\"data\":\"...\",\"nonce\":\"...\"}","signature":"<base64>"}
```

- `payload` is the JSON string `{"data":<body>,"nonce":<UUIDv7>}`. Every non-ASCII and control character is escaped, so the payload is always printable ASCII and can go straight into an HTTP header.
- `signature` is the Ed25519 signature of the payload's ASCII bytes, base64-encoded.
- Every call generates a new nonce, so signing the same body twice gives different results.
- The body must be valid UTF-8; otherwise the response is 400.

### `POST /Auth/verify`

Verifies a request that carries `X-Sign-*` headers. A request that passes gets `200 {"verified":true}`; anything else gets `401 {"verified":false}`, with no reason given.

| Header | Content |
|---|---|
| `X-Sign-Version` | Always `2` |
| `X-Sign-Domain` | Always `five-gaming` |
| `X-Sign-Nonce` | UUIDv7; must equal the `nonce` in the payload |
| `X-Sign-Payload` | `{"data":...,"domain":...,"nonce":...}`; `data` must equal the request body |
| `X-Sign-Signature` | The intermediate key's signature of the payload (base64, 64 bytes) |
| `X-Sign-Intermediate-Public-Key` | The intermediate public key (base64, 32 bytes) |
| `X-Sign-Intermediate-Signature` | The root key's signature of the intermediate certificate (base64, 64 bytes) |
| `X-Sign-Intermediate-Not-Before` / `-Not-After` | The intermediate certificate's validity period (Unix seconds) |

Verification steps:

1. Verify the signature of the intermediate certificate `{"not_after":<seconds>,"not_before":<seconds>,"public_key":"<base64>"}` with `ROOT_PUBLIC_KEY`, and check that the current time is within its validity period.
2. Verify the payload's signature with the intermediate public key.
3. Check that `domain`, `nonce` and `data` in the payload match `X-Sign-Domain`, `X-Sign-Nonce` and the request body.
4. The nonce's timestamp (the first 48 bits of the UUIDv7) must be no more than 5 minutes in the past and no more than 60 seconds in the future.
5. Each nonce can be used only once, to prevent replay attacks.

Each header must appear exactly once; a repeated header also fails verification.

All five examples apply exactly the same format rules, and anything that breaks them gets 401:

- **base64**: must be standard base64: length a multiple of 4, `=` padding present, no whitespace. base64url is not accepted.
- **Not-Before / Not-After**: must match `^-?[0-9]+$`. `+123` and surrounding whitespace are rejected.
- **payload**:
  - Must be valid UTF-8, with no leading BOM.
  - Must be a JSON object, with keys matching exactly, including case.
  - Every key and string must be well-formed Unicode, with no lone surrogates (such as `\udcff`). This applies to unused fields too.
  - When a key is repeated, the last one wins.
  - Nesting is limited to 64 levels, counting the outer object as level 1. A normal payload is 1 level deep.

### Error responses

| Situation | Response |
|---|---|
| The sign body is not valid UTF-8 | `400 {"error":"body is not valid UTF-8"}` |
| The body is larger than 8 MiB | `413 {"error":"body is too large"}` |
| Verification fails | `401 {"verified":false}` |

Any other unexpected error returns 500. Go, Node and PHP return `{"error":"internal server error"}`; in C# and Java the framework decides the format. PHP also returns `{"error":"not found"}` (404) and `{"error":"method not allowed"}` (405); the other examples use their framework's default 404 and 405 responses. No error response includes a stack trace or other internal details, and failed verifications are not logged.

## Configuration

All five examples use the same environment variables:

| Variable | Content |
|---|---|
| `KEY_ID` | Returned as `key_id` in the sign response |
| `OPERATOR_ID` | Returned as `operator_id` in the sign response |
| `PRIVATE_KEY` | The operator's Ed25519 private key: the 32-byte raw seed, base64-encoded (not PKCS#8) |
| `ROOT_PUBLIC_KEY` | The platform root's Ed25519 public key: the 32-byte raw key, base64-encoded (not SPKI) |
| `PORT` | The port to listen on, `8080` by default (C# uses ASP.NET Core's `ASPNETCORE_URLS` / `ASPNETCORE_HTTP_PORTS`) |

When the configuration is invalid (missing, not base64, or not 32 bytes), the app lists every problem at startup and exits. PHP has no startup phase, so it returns 500 to every request and writes the reasons to the error log. Error messages never include the configured values.

One difference remains: a `ROOT_PUBLIC_KEY` that is 32 bytes long but is not a usable Ed25519 public key (for example all zero bytes). Java checks for this and refuses to start with `ROOT_PUBLIC_KEY is not a valid Ed25519 public key`. The other four examples start normally, and every verify request fails with 401, because Go's and Node's standard libraries have no API to validate a public key on its own.

## Running

To start an example locally, you can use these fixed test keys. They are the same keys the tests use: the private key is the seed with every byte set to `0x01`, and the root public key belongs to the seed with every byte set to `0x02`. Never use them in production.

```sh
export KEY_ID=test-key
export OPERATOR_ID=test-operator
export PRIVATE_KEY=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
export ROOT_PUBLIC_KEY=gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=
```

### Running and testing locally

| Example | Start | Test |
|---|---|---|
| C# | `dotnet run --project src/CsharpEd25519Example` | `dotnet test` |
| Go | `go run .` | `go test ./...` |
| Java (requires JDK 25) | `./mvnw spring-boot:run` | `./mvnw test` |
| Node | `npm ci && npm start` | `npm test` |
| PHP (requires APCu) | `composer install && composer start` | `composer test`, or `composer test:docker` without APCu |

Run each command in its example's directory.

### Docker

Each example directory has a Dockerfile, and every image runs as a non-root user:

```sh
docker build -t node-ed25519-example node-ed25519-example
docker run --rm -p 8080:8080 -e KEY_ID -e OPERATOR_ID -e PRIVATE_KEY -e ROOT_PUBLIC_KEY node-ed25519-example
```

## Shared test cases

[testdata/payload-escaping-cases.json](testdata/payload-escaping-cases.json) holds 173 request bodies, covering control characters, all kinds of Unicode, BOMs, invalid UTF-8 and more. Every example's tests read this file and check that the payload produced by sign:

- is printable ASCII
- is valid JSON
- has a `data` field that decodes back to exactly the original body
- has a signature that verifies

Cases marked `rejected: true` must get 400 instead.

To add a case, edit this one file and all five examples pick it up.

## Deployment notes

- **Replay protection only works within a single process.** Used nonces are kept in memory for 6 minutes (PHP keeps them in APCu, shared by the Apache workers on one machine). With several instances, the same request can be used once on each instance. To block replays across instances, store nonces in shared storage instead (for example Redis `SET key value NX EX 360`).
- **A restart clears the nonce record.** For 6 minutes after a restart, nonces used before the restart can be used again.
- **X-Sign-Payload carries the whole body.** Any proxy or load balancer in front must also allow 8 MiB headers, or large requests are rejected before they reach the service.
