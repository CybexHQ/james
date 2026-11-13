"""The Management origins a production Nest release may be built for.

Production Manage is `https://manage.tiaris.com`. Production Nest releases up to
and including v0.2.99 were built for its former name, `https://manage.cybex.net`.
Both names are production: a release built for either may be published, while
the release lineage (`tools/nest-release.py`) admits the change between them
exactly once, from the former name to the current one, and never back.

`src/provisioning/mod.rs` `PRODUCTION_MANAGE_ORIGIN` is the Rust copy of the
current name; a test keeps the two equal.
"""

PRODUCTION_MANAGE_ORIGIN = "https://manage.tiaris.com"
FORMER_PRODUCTION_MANAGE_ORIGIN = "https://manage.cybex.net"
PRODUCTION_MANAGE_ORIGINS = (PRODUCTION_MANAGE_ORIGIN, FORMER_PRODUCTION_MANAGE_ORIGIN)


def is_production(origin: object) -> bool:
    return isinstance(origin, str) and origin in PRODUCTION_MANAGE_ORIGINS


def require_production(origin: object, message: str) -> str:
    if not is_production(origin):
        raise ValueError(message)
    return origin
