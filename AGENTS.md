# Wallet instance demo agent instructions

This repository is the IT-Wallet instance demo. It obtains credentials from the OpenID4VCI issuer in iam-proxy-italia and presents them. The normative text is the IT-Wallet Technical Specifications. Editorial rules of that Sphinx repository apply only when editing that repository.

## Where content lives

- Pages and routes: `app/templates/`, `app/routes/`.
- Italian is the source language of every user-facing string. The English sentence is the `msgstr` of that same `msgid` in `app/translations/en/LC_MESSAGES/messages.po`, compiled to `messages.mo`.
- Held credentials and revocation state: `app/store/credential_store.py`.
- Issuance and status HTTP calls: `app/utils/itwalletUtils.py`.

## Specification

Implement the behavior the specification states. Do not copy the same check into a second function. Call the function that owns it.

Do not weaken or strengthen a specified behavior unless the user asks. When the user asks for a divergence, keep that divergence explicit in the change.

Revocation is read from the Status List in the credential (`status.status_list.uri` and `idx`). Do not call a status assertion endpoint.

The Italian message and the English message state the same fact. One sentence states one outcome. A success message reports that outcome, not that an update occurred.

Example hostnames stay under `example.org`.

## Git

Do not create a commit, and do not push, unless the user asks for that in the current request.

## Editing

Change only the requested part. Do not rewrite neighboring code, templates, or translations for style.
