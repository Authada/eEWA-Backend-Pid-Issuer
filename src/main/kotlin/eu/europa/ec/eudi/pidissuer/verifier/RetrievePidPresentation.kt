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
package eu.europa.ec.eudi.pidissuer.verifier

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Attributes
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.FamilyName
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GivenName
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Pid
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMetaData
import eu.europa.ec.eudi.sdjwt.JwtSignatureVerifier
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asClaims
import eu.europa.ec.eudi.sdjwt.recreateClaimsAndDisclosuresPerClaim
import kotlinx.serialization.json.jsonPrimitive

class RetrievePidPresentation(
    private val getWalletResponse: GetWalletResponse
) {
    suspend operator fun invoke(presentationSession: PresentationSession, responseCode: String): Pid {
        val response = getWalletResponse(presentationSession.transactionId, responseCode)

        val presentation = SdJwtVerifier.verifyPresentation({
            val parsedJwt = SignedJWT.parse(it)
            parsedJwt.jwtClaimsSet.asClaims()
        }, eu.europa.ec.eudi.sdjwt.KeyBindingVerifier.MustBePresentAndValid {
            JwtSignatureVerifier {
                val parsedJwt = SignedJWT.parse(it)
                parsedJwt.jwtClaimsSet.asClaims()
            }
        }, response.credentials!!.first().credential)

        val claims = presentation.getOrThrow().recreateClaimsAndDisclosuresPerClaim {
            it.second
        }.first

        return Pid(
            familyName = claims[Attributes.FamilyName.name]?.jsonPrimitive?.content?.let { FamilyName(it) },
            givenName = claims[Attributes.GivenName.name]?.jsonPrimitive?.content?.let { GivenName(it) },
            metaData = PidMetaData()
        )
    }
}
