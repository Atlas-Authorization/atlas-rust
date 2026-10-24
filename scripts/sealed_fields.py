#!/usr/bin/env python3
"""Add the `sealed_*` fields to the generated response structs that carry a
shown-once secret.

Atlas seals every shown-once secret in an answer to the key named in the
`X-Secret-Recipient` request header: the plaintext field is replaced by
`sealed_<field>` and `secrets_sealed` names what was sealed. The OpenAPI response
schemas document the plaintext field only (the header is declared on the
operation), so the generator calls `add_sealed_fields` on the emitted
`types.rs`. Running this file applies it to `src/backend/types.rs` in place
(idempotent).
"""
import os
import re
import sys

SEALABLE = ('secret', 'client_secret', 'webhook_secret', 'request_secret', 'poll_secret',
            'completion_webhook_secret')
# Minting responses whose `token` is sealed.
TOKEN_STRUCTS = ('ScimTokensCreateResponse', 'OAuthInitialAccessTokensCreateResponse', 'SignInToken',
                 'ActorToken', 'SsoOnboardingCreateTicketResponse')

SECRETS_SEALED = '''
/// Says a response was sealed to the key sent as `X-Secret-Recipient`: each listed
/// field arrives as `sealed_<field>` instead of in plaintext (open it with
/// `open_sealed_secret`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecretsSealed {
    /// The sealing algorithm.
    #[serde(default)]
    pub algorithm: String,
    /// The recipient key the values were sealed to.
    #[serde(default)]
    pub recipient: String,
    /// The plaintext field names that arrived sealed.
    #[serde(default)]
    pub fields: Vec<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
'''


def add_sealed_fields(src: str) -> str:
    marker = '    /// Fields this version of the crate does not know about, kept verbatim.\n'

    def patch(m):
        name, body = m.group(1), m.group(2)
        if 'Body' in name or name == 'SecretsSealed' or 'secrets_sealed' in body:
            return m.group(0)
        fields = [f for f in re.findall(r'\n    pub (\w+): (?:Option<)?String>?,', body) if f in SEALABLE]
        if name in TOKEN_STRUCTS and re.search(r'\n    pub token: ', body):
            fields.append('token')
        if not fields or marker not in body:
            return m.group(0)
        add = ''
        for f in fields:
            sealed = 'sealed_' + f
            if ('pub %s:' % sealed) in body:
                continue
            add += ('    /// With an `X-Secret-Recipient`: `%s` sealed to it (then `%s` is absent).\n'
                    '    #[serde(default, skip_serializing_if = "Option::is_none")]\n'
                    '    pub %s: Option<String>,\n') % (f, f, sealed)
        add += ('    /// With an `X-Secret-Recipient`: the fields that arrived sealed.\n'
                '    #[serde(default, skip_serializing_if = "Option::is_none")]\n'
                '    pub secrets_sealed: Option<SecretsSealed>,\n')
        body = body.replace(marker, add + marker, 1)
        return 'pub struct %s {%s\n}\n' % (name, body)

    out = re.sub(r'pub struct (\w+) \{(.*?)\n\}\n', patch, src, flags=re.S)
    if 'pub struct SecretsSealed' not in out:
        out = out.rstrip('\n') + '\n' + SECRETS_SEALED
    return out


if __name__ == '__main__':
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src/backend/types.rs')
    if len(sys.argv) > 1:
        path = sys.argv[1]
    text = open(path).read()
    new = add_sealed_fields(text)
    if new != text:
        open(path, 'w').write(new)
    print('sealed fields: %s' % ('updated' if new != text else 'already present'))
