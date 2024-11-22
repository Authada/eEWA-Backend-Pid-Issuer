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
package eu.europa.ec.eudi.pidissuer.adapter.out.msisdn

import eu.europa.ec.eudi.pidissuer.adapter.input.web.MsisdnUi
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Attributes
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.input.ClientId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriRepeatable
import eu.europa.ec.eudi.pidissuer.verifier.RequestPidPresentation
import eu.europa.ec.eudi.pidissuer.verifier.RetrievePidPresentation
import io.ktor.http.encodeURLParameter
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.time.LocalDate


class AuthorizeMsisdn(
    private val getAuthorizationSessionByRequestUriRepeatable: GetAuthorizationSessionByRequestUriRepeatable,
    private val requestPidPresentation: RequestPidPresentation,
    private val retrievePidPresentation: RetrievePidPresentation,
    private val issuerPublicUrl: HttpsUrl
) {
    suspend fun start(requestUri: URI, clientId: ClientId): URI {
        val session = getAuthorizationSessionByRequestUriRepeatable(requestUri, clientId)
        if (session.presentationSession == null) {
            session.presentationSession = requestPidPresentation(
                UriComponentsBuilder.fromUriString(issuerPublicUrl.externalForm)
                    .path(MsisdnUi.MSISDN)
                    .queryParam("request_uri", requestUri.toString())
                    .queryParam("client_id", clientId.encodeURLParameter())
                    .queryParam("response_code", "{RESPONSE_CODE}")
                    .build()
                    .toString(),
                Attributes.FamilyName,
                Attributes.GivenName
            )
            return session.presentationSession!!.uri
        }

        return session.presentationSession!!.uri
    }


    suspend fun complete(requestUri: URI, clientId: ClientId, responseCode: String) {
        val session = getAuthorizationSessionByRequestUriRepeatable(requestUri, clientId)
        val presentationSession = session.presentationSession ?: throw IllegalStateException()
        val data = retrievePidPresentation(presentationSession, responseCode)
        session.msisdn = MsisdnData(
            phoneNumber = "+490000000000",
            issuanceDate = LocalDate.now(),
            expiryDate = LocalDate.now().plusDays(356),
            registeredGivenName = data.givenName!!.value,
            registeredFamilyName = data.familyName!!.value,
            contractOwner = true,
            endUser = true,
            mobileOperator = "TestOperator",
            issuingOrganization = "Test issuing organization",
            verificationDate = LocalDate.now(),
            verificationMethodInformation = "PID Presentation",
        )
    }

}
