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
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import de.bund.bsi.eid.EID
import de.bund.bsi.eid.GetResultRequestType
import de.bund.bsi.eid.SessionType
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import oasis.names.tc.dss._1_0.core.schema.Result
import org.slf4j.LoggerFactory
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.util.UUID

sealed interface EidResultError {

    val errorDescription: String

    data object Generic : EidResultError {
        override val errorDescription: String = ""
    }

    data class RedirectError(val uri: URI, override val errorDescription: String) : EidResultError

}

class HandleEidResult(
    private val client: EID,
    private val getAuthorizationSessionByRequestUriOnce: GetAuthorizationSessionByRequestUriOnce,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val createAuthorizationCodeUri: CreateAuthorizationCodeUri
) {
    context(Raise<EidResultError>)
    suspend operator fun invoke(requestUri: URI, clientId: String, clientResultMajor: String): URI {
        //TODO validate clientResultMajor
        log.info("Client result {}", clientResultMajor)
        val session = getAuthorizationSessionByRequestUriOnce(requestUri, clientId)
        val getResultResponseType = client.getResult(GetResultRequestType().apply {
            this.requestCounter = session.eidRequestCounter++
            this.session = SessionType().apply {
                this.id = session.eidSessionId
            }
        })
        checkResult(getResultResponseType.result, session.authRequest)
        session.eidData = getResultResponseType.personalData
        session.ageVerificationResult = getResultResponseType.fulfilsAgeVerification?.isFulfilsRequest
        val newRequestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}") //TODO extract
        storeRequestUriReference(newRequestUri, clientId, session.id)
        return createAuthorizationCodeUri(session.authRequest.redirectionURI, newRequestUri.toString(), session.authRequest.state)
    }

    context(Raise<EidResultError>)
    private fun checkResult(result: Result, authRequest: AuthorizationRequest) {
        log.info(
            "EID Result Major {}, Minor {}, message {}",
            result.resultMajor,
            result.resultMinor,
            result.resultMessage
        )
        ensure(result.resultMajor.contentEquals("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok", true)) {
            raise(EidResultError.RedirectError(
                UriComponentsBuilder
                    .fromUriString(authRequest.redirectionURI.toString())
                    .apply {
                        authRequest.state?.let {
                            queryParam("state", it)
                        }
                        queryParam("error", "Authentication failed")
                        queryParam("errorDescription", "eID authentication failed")
                    }
                    .build()
                    .toUri(), "Error during authentication"))
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(HandleEidResult::class.java)
    }

}
