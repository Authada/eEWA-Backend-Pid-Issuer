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
package eu.europa.ec.eudi.pidissuer.patch

import arrow.core.raise.Raise
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.id.ClientID
import eu.europa.ec.eudi.pidissuer.adapter.input.web.TokenApi
import eu.europa.ec.eudi.pidissuer.domain.WAVError
import org.slf4j.LoggerFactory

class WalletClientAttestation(
    private val walletAttestationJws: SignedJWT,
    private val walletAttestationPopJws: SignedJWT,
    clientID: ClientID?
) : ClientAuthentication(ClientAuthenticationMethod.ATTEST_JWT_CLIENT_AUTH, clientID) {
    companion object {
        fun fromFormData(formData: Map<String, MutableList<String>>): WalletClientAttestation? {
            log.info("Parsing wallet client attestation")
            val assertionType = formData.get(assertionTypeFieldName)?.first()
            if (assertionType == null || assertionType != typeUrn) {
                return null
            }

            val assertion =
                formData.get(assertionFieldName)?.first() ?: throw ParseException("Invalid client assertion")

            val parts = assertion.split("~")
            if (parts.size != 2) {
                throw ParseException("Invalid client assertion structure")
            }

            val clientId =
                formData.get("client_id")?.first()?.let { ClientID(it) } ?: throw ParseException("Invalid client id")

            val walletAttestationString = parts[0]
            val walletAttestationPopString = parts[1]

            try {
                val walletAttestationJws = SignedJWT.parse(walletAttestationString)
                val walletAttestationPopJws = SignedJWT.parse(walletAttestationPopString)

                log.info("Parsed wallet client attestation")
                return WalletClientAttestation(walletAttestationJws, walletAttestationPopJws, clientId)
            } catch (e: java.text.ParseException) {
                throw ParseException("Invalid JWTs in client attestation", e)
            }
        }


        const val assertionFieldName = "client_assertion"
        const val assertionTypeFieldName = "client_assertion_type"
        const val clientIdFieldName = "client_id"
        private const val typeUrn = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
        const val methodName = "attest_jwt_client_auth"
        private val log = LoggerFactory.getLogger(TokenApi::class.java)
    }

    context(Raise<WAVError>)
    suspend fun validate(validate: suspend (SignedJWT, SignedJWT) -> Unit) =
        validate(walletAttestationJws, walletAttestationPopJws)

    override fun getFormParameterNames(): MutableSet<String> =
        mutableSetOf(assertionFieldName, assertionTypeFieldName, clientIdFieldName)

    override fun applyTo(httpRequest: HTTPRequest?) {
        throw UnsupportedOperationException()
    }
}
