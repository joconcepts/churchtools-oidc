# church-oidc

Go port of `../java`: wraps a ChurchTools OAuth "social login" in a minimal
OpenID Connect provider, so OIDC-only tools can authenticate against
ChurchTools. Single static binary, in-memory state, stdlib only (no
dependencies — the RS256 signing is hand-rolled from `crypto/rsa`).

## Run

```bash
go build -o church-oidc .
./church-oidc
```

## Docker

```bash
docker build -t church-oidc .
docker run --rm -p 8080:8080 --env-file .env church-oidc
```

Pushed to `ghcr.io/<owner>/<repo>:latest` by `.github/workflows/docker.yml`
on every push to `main`/`master` (also tagged with the commit SHA). The
package is private by default on first publish — make it public, or grant
pull access, in the repo's Packages settings if it needs to be pulled
anonymously.

The signing key is a fresh RSA-2048 keypair generated at startup (matches
the Java app, which has no `JWKSource` bean and so also generates one). It
is not persisted, so tokens don't survive a restart — expected for a
single-instance proxy.

## Configuration (environment variables)

Example deployment: this service at `https://openid-customapp.yourchurch.de`,
the external app at `https://custom-app.yourchurch.de`.

| Variable                              | Example                                                                 | Notes                                    |
|----------------------------------------|--------------------------------------------------------------------------|-------------------------------------------|
| `OAUTH_SOCIAL_LOGIN_CLIENT_ID`         | clientId from ChurchTools                                                |                                             |
| `OAUTH_SOCIAL_LOGIN_SECRET`            | random string                                                             |                                             |
| `OAUTH_SOCIAL_LOGIN_REDIRECTURI`       | `https://openid-customapp.yourchurch.de/login/oauth2/code/custom-client` | path must stay exactly this                |
| `OAUTH_SOCIAL_LOGIN_AUTHORIZATION_URI` | `https://yourchurch.church.tools/oauth/authorize`                        |                                             |
| `OAUTH_SOCIAL_LOGIN_TOKEN_URI`         | `https://yourchurch.church.tools/oauth/access_token`                     |                                             |
| `OAUTH_SOCIAL_LOGIN_USER_INFO_URI`     | `https://yourchurch.church.tools/oauth/userinfo`                         |                                             |
| `OPENID_SUB`                           | `userName`                                                                | which ChurchTools attribute becomes `sub`: `userName`, `email`, or `id` |
| `OPENID_ISSUER`                        | `https://openid-customapp.yourchurch.de`                                 |                                             |
| `OPENID_CLIENT_ID`                     | your own client id                                                        |                                             |
| `OPENID_CLIENT_SECRET`                 | your own client secret                                                    |                                             |
| `OPENID_REDIRECT_URI`                  | `https://custom-app.yourchurch.de/oauth2/callback`                       |                                             |
| `PORT`                                 | `8080`                                                                    | optional, defaults to 8080                 |

## Endpoints

* `GET /.well-known/openid-configuration`
* `GET /oauth2/jwks`
* `GET /oauth2/authorize`
* `GET /login/oauth2/code/custom-client` — ChurchTools callback (fixed path)
* `POST /oauth2/token` — `authorization_code` (PKCE/S256 required) and `refresh_token` grants
* `GET|POST /userinfo`

## JWT claims

* Scope `openid`: `sub`
* Scope `profile`: `preferred_username`, `given_name`, `family_name`, `name`, `profile`
* Scope `email`: `email`

## Test

```bash
go test ./...
```
