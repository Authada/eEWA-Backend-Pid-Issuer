/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import com.nimbusds.oauth2.sdk.token.TokenTypeURI
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.ValidateWalletAttestation
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequestError.InvalidRequest
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateCNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreAccessTokenMetaByToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import eu.europa.ec.eudi.pidissuer.port.out.persistence.UpsertCNonce
import org.slf4j.LoggerFactory
import java.net.URI
import java.time.Clock
import java.time.Instant
import java.util.UUID


/**
 * Errors that might be returned by [CreateCredentialsOffer].
 */
sealed interface AccessTokenRequestError {

    /**
     * No Credentials Unique Ids have been provided.
     */
    data object Test : AccessTokenRequestError

    /**
     * The provided Credential Unique Ids are not valid.
     */
    data class InvalidRequest(val test: String) : AccessTokenRequestError
}

class AccessTokenRequest(
    private val getAuthorizationSessionByRequestUriOnce: GetAuthorizationSessionByRequestUriOnce,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val storePrincipal: StoreAccessTokenMetaByToken,
    private val clock: Clock,
    private val dPoPProperties: DPoPConfigurationProperties,
    private val credentialIssuerId: CredentialIssuerId,
    private val validateWalletAttestation: ValidateWalletAttestation,
    private val upsertCNonce: UpsertCNonce,
    private val generateCNonce: GenerateCNonce,
    ) {
    context(Raise<AccessTokenRequestError>)
    suspend operator fun invoke(
        requestParams: TokenRequest,
        dPoP: com.nimbusds.jwt.SignedJWT,
        walletClientAttestation: WalletClientAttestation
    ): Pair<DPoPAccessToken, CNonce> {
        either {
            walletClientAttestation.validate { attestation, attestationPop ->
                validateWalletAttestation(
                    requestParams.clientID.value,
                    credentialIssuerId,
                    attestation,
                    attestationPop
                )
            }
        }.getOrElse {
            raise(InvalidRequest(""))
        }
        val authorizationCodeGrant = requestParams.authorizationGrant as AuthorizationCodeGrant
        log.info("AuthorizationCodeGrand {}", authorizationCodeGrant)

        val clientId = requestParams.clientID.value
        val session = getAuthorizationSessionByRequestUriOnce(
            URI(authorizationCodeGrant.authorizationCode.value),
            clientId
        )
        log.info("Session retrieved")
        val computedCodeChallenge =
            CodeChallenge.compute(session.authRequest.codeChallengeMethod, authorizationCodeGrant.codeVerifier)
        val parsedCodeChallenge = CodeChallenge.parse(session.authRequest.codeChallenge.value)

        log.info("Code challenge computed {} : {}", computedCodeChallenge.value, parsedCodeChallenge.value)

        if (parsedCodeChallenge != computedCodeChallenge) {
            log.info("Code verifier invalid")
            raise(InvalidRequest("")) //TODO proper message
        }

        log.info("Generating new request_uri")
        val requestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}")
        storeRequestUriReference(requestUri, clientId, session.id)

        log.info("Storing principal information")
        val jwkThumbprint = dPoP.header.jwk.computeThumbprint()
        val validatedScope = session.authRequest.scope ?: Scope.parse(session.matchedAttributeDetails.keys.map { it.value }) // TODO validate with auth request
        storePrincipal(
            requestUri.toString(),
            AccessTokenMetadata(
                clientId = clientId, // TODO evtl. aus dpop rausholen?
                jwkThumbprint = jwkThumbprint,
                expiration = (clock.instant() + dPoPProperties.proofMaxAge),
                notBefore = clock.instant(),
                validatedScope!!.toStringList()
            )
        )

        log.info("Generating accesstoken for jwk thumbprint {}", jwkThumbprint.toString())
        val dPoPAccessToken = DPoPAccessToken(
            requestUri.toString(),
            300L,
            validatedScope,
            session.authRequest.authorizationDetails,
            TokenTypeURI.ACCESS_TOKEN
        )
        val cnonce = generateCNonce(dPoPAccessToken.toAuthorizationHeader(), clock)
        upsertCNonce(cnonce)
        return dPoPAccessToken to cnonce
    }


    data class AccessTokenMetadata(
        val clientId: String,
        val jwkThumbprint: Base64URL,
        val expiration: Instant,
        val notBefore: Instant,
        val scope: List<String>
    )

    companion object {
        private val log = LoggerFactory.getLogger(AccessTokenRequest::class.java)
    }
}
