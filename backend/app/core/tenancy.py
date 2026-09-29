"""Small helpers for keeping tenant scoping consistent across API queries."""

def tenant_id(user: dict | None) -> str:
    return str((user or {}).get("org_id") or "default")

def tenant_filter(user: dict | None) -> dict:
    org = tenant_id(user)
    # Existing local data predates tenancy and belongs to the default tenant.
    return {"$or": [{"org_id": org}, {"org_id": {"$exists": False}}]} if org == "default" else {"org_id": org}

def scoped_query(user: dict | None, *conditions: dict) -> dict:
    return {"$and": [tenant_filter(user), *conditions]}
