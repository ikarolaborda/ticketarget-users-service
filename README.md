# TicketArget — Users Service

Laravel 13 (FrankenPHP) service owning accounts and authentication: registration,
login, and stateless HS256 bearer tokens (strict, fixed-algorithm JWTs) that any
platform service can verify with the shared `AUTH_JWT_SECRET`.

Endpoints: `POST /auth/register`, `POST /auth/login` (throttled), `GET /auth/me`.
Guests can still buy tickets without an account by providing an email at checkout.

Part of the [TicketArget platform](https://github.com/ikarolaborda/ticketarget) —
run it from the aggregator repo, which provides the Docker topology and shared
`ticketarget/logging` package.
