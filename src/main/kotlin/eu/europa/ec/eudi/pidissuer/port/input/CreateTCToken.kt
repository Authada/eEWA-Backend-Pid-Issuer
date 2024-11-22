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
import de.bund.bsi.eid.AgeVerificationRequestType
import de.bund.bsi.eid.AttributeRequestType.ALLOWED
import de.bund.bsi.eid.AttributeRequestType.REQUIRED
import de.bund.bsi.eid.EID
import de.bund.bsi.eid.OperationsRequestorType
import de.bund.bsi.eid.UseIDRequestType
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import org.slf4j.LoggerFactory
import java.net.URI
import java.util.UUID

sealed interface TCTokenError {

    /**
     * No Credentials Unique Ids have been provided.
     */
    data object Generic : TCTokenError

    /**
     * The provided Credential Unique Ids are not valid.
     */
    data class CommunicationErrorAdress(val communicationErrorAddressURI: URI) : TCTokenError
}

data class TCToken(
    val serverAddress: String,
    val sessionIdentifier: String,
    val refreshAddressURI: URI,
    val psk: String,
)

class CreateTCToken(
    private val client: EID,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val getAuthorizationSessionByRequestUriOnce: GetAuthorizationSessionByRequestUriOnce,
) {
    context(Raise<TCTokenError>)
    @OptIn(ExperimentalStdlibApi::class)
    suspend operator fun invoke(requestUri: URI, clientId: String): TCToken {
        log.info("searching request uri {} with clientId {}", requestUri, clientId)
        val session = getAuthorizationSessionByRequestUriOnce(requestUri, clientId)
        val newRequestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}") //TODO extract
        storeRequestUriReference(newRequestUri, clientId, session.id)
        val createRequest = createRequest(session.matchedAttributeDetails.values.flatMap { it })
        val useIDResponseType = client.useID(createRequest)
        session.eidSessionId = useIDResponseType.session.id
        return TCToken(
            useIDResponseType.eCardServerAddress,
            useIDResponseType.psk.id,
            newRequestUri,
            psk = useIDResponseType.psk.key.toHexString()
        )
    }


    companion object {
        private val log = LoggerFactory.getLogger(CreateTCToken::class.java)
    }

    fun createRequest(attributeDetails: List<AttributeDetails>): UseIDRequestType =
        UseIDRequestType().apply {
            this.useOperations = OperationsRequestorType()
            //TODO refactor, prepare and validate in par endpoint
            attributeDetails.forEach {
                log.info("Setting eID Field '${it.name}' to required")
                it.operationSetter?.invoke(this.useOperations, REQUIRED)
            }
            this.useOperations.dateOfExpiry = REQUIRED
            if (this.useOperations.ageVerification in arrayOf(REQUIRED, ALLOWED)) {
                this.ageVerificationRequest = AgeVerificationRequestType().apply {
                    this.age = 18
                }
            }
        }
}

