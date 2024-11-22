# Eudi (PID) Issuer

Based on EU reference implementation commit 2e8784b5a3acae2b38faee57f67696aa4fbb2eeb

See https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/commit/2e8784b5a3acae2b38faee57f67696aa4fbb2eeb

# Changes made in phase 2
- Added signed_metadata containing a signed jwt signed by a trusted anchor which is checked by the authada wallet app prototype
- Added mdl credential in mdoc format with basic login UI
- Added pre-authorized flow for new credentials
- Added pre-authorized flow msisdn credential in sd-jwt format with pid presentation during issuing
- Added pre-authroized email credential in sd-jwt and mdoc format with basic email input ui
- Updated doctype and attributes for pid sd-jwt format
- Added validation of wallet provider attestation with chain validation (trust management for wallet attestation)
- Refactoring issuing logic to support fast addition of new credentials
- Added verifier client for starting presentations during issuing
- Add new UI overview/home pages

# Changes made in phase 1:
- Removed dependency on Keycloak/authorization server
- Added OAuth 2.0 endpoints:
  - authorization server metadata endpoint
  - pushed authorization request endpoint
  - authorization request endpoint
  - authorization code endpoint
  - token endpoint with DPoP support
- Added GET method to pushed authorization endpoint to get cnonce for wallet attestation PoP
- Added wallet/client attestation based on https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-02 to pushed authorization request endpoint
- Added wallet/client attestation requirement to pushed authorization and token endpoints
- Added authorization details support to pushed authorization request to support eid chat configuration based on authorization details
- Added rudimentary eid client/server integration according to TR-03130-1.
  - made authorization request redirect to eid client scheme to open the eid client without custom modifications in the OAuth 2.0 client
  - added tctoken endpoint generating a tctoken for the eid client. Creates eid session with chat derived from authorization details.
  - added authorization code endpoint as refresh/communicationerror-address endpoints
  - refresh address endpoint called by the browser retrieves eid data and redirects to redirect uri provided in the pushed authorization request including the authorization code on success and error parameter on error.
- Added DPoP requirement to credential request endpoint
- Bridged OAuth 2.0 endpoints to credential request/issuing endpoint by implementing a local PID provider accessing eid session result data referenced by the DPoP token created through token endpoint
- Added authenticated channel support to credential issuing by specifying verifier-ka field in credential request. Marking support for authenticated channel by adding algorithms specified in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-02 to metadata of respective credential configuration.
- Implemented authenticated channel for SD-JWT according to https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-02.
- Implemented authenticated channel for mdoc by implementing custom signer with new algorithmid to signal authenticated channel in issuerSigned/issuerAuth.
- Added se-tlv format with new credential configuration for issuing pid contents with pid issuer certificate to secure element as new credential format
- Changed SD-JWT VC PID contents to match EU ARF
- Only authorization code flow is supported
- Wallet attestation is mandatory
- Rudimentary error handling
- Trust management for wallet attestation not implemented yet
