DEFAULT_PARSED_SECRET_VALUE = {
    "name": "overwrite-me",
    "fields": {},
    "base64": [],
    "ini_file": {},
    "generate": [],
    "override": [],
    "vault_mount": "secret",
    "vault_policies": {},
    "vault_prefixes": ["hub"],
    "type": "Opaque",
    "namespace": "validated-patterns-secrets",
    "labels": {},
    "annotations": {},
    "paths": {},
}

DEFAULT_KUBERNETES_METADATA = {
    "name": "overwrite-me",
    "labels": {},
    "annotations": {},
    "namespace": "validated-patterns-secrets",
}
DEFAULT_KUBERNETES_SECRET_OBJECT = {
    "kind": "Secret",
    "type": "Opaque",
    "apiVersion": "v1",
    "metadata": DEFAULT_KUBERNETES_METADATA,
    "stringData": {},
}

DEFAULT_VAULT_POLICIES = {
    "validatedPatternDefaultPolicy": (
        "length=20\n"
        'rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }\n'
        'rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }\n'
        'rule "charset" { charset = "0123456789" min-chars = 1 }\n'
        'rule "charset" { charset = "!@#%^&*" min-chars = 1 }\n'
    ),
}
