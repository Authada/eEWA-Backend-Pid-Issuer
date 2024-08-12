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

import arrow.core.raise.Raise
import arrow.core.raise.ensure
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.domain.WAVError

class WalletClientAttestation(
    private val walletAttestationJws: SignedJWT,
    private val walletAttestationPopJws: SignedJWT
) {
    companion object {
        context(Raise<PARError>)
        fun fromFormData(formData: Map<String, MutableList<String>>): WalletClientAttestation? {


            val assertionType = formData.get(assertionTypeFieldName)?.first()
            if (assertionType == null || assertionType != typeUrn) {
                return null
            }

            val assertion = formData.get(assertionFieldName)?.first()
            ensure(assertion != null) {
                raise(PARError.InvalidClientAssertion)
            }

            val parts = assertion.split("~")
            ensure(parts.size == 2) {
                raise(PARError.InvalidClientAssertion)
            }

            val walletAttestationString = parts[0]
            val walletAttestationPopString = parts[1]

            val walletAttestationJws = SignedJWT.parse(walletAttestationString)
            val walletAttestationPopJws = SignedJWT.parse(walletAttestationPopString)

            return WalletClientAttestation(walletAttestationJws, walletAttestationPopJws)
        }


        const val assertionFieldName = "client_assertion"
        const val assertionTypeFieldName = "client_assertion_type"
        private const val typeUrn = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
        const val methodName = "attest_jwt_client_auth"
    }

    context(Raise<WAVError>)
    suspend fun validate(validate: suspend (SignedJWT, SignedJWT) -> Unit) =
        validate(walletAttestationJws, walletAttestationPopJws)
}
