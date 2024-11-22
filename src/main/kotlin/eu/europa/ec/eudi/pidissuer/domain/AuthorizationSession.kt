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
package eu.europa.ec.eudi.pidissuer.domain

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import de.bund.bsi.eid.PersonalDataType
import eu.europa.ec.eudi.pidissuer.adapter.out.email.Email
import eu.europa.ec.eudi.pidissuer.adapter.out.msisdn.MsisdnData
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType
import eu.europa.ec.eudi.pidissuer.verifier.PresentationSession
import java.util.UUID

data class AuthorizationSession(
    val authRequest: AuthorizationRequest,
    val matchedAttributeDetails: Map<Scope, List<AttributeDetails>>,
    val authenticationType: AuthenticationType
) {
    var eidData: PersonalDataType? = null
    var ageVerificationResult: Boolean? = null
    var eidSessionId: ByteArray? = null
    var eidRequestCounter: Int = 1
    val id = UUID.randomUUID()
    var email: Email? = null
    var msisdn: MsisdnData? = null
    var presentationSession: PresentationSession? = null
}
