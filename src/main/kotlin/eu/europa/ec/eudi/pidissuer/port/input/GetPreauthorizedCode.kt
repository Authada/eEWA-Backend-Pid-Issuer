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

import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import java.net.URI
import java.util.UUID

data class PreAuthorizedCodeData(
    val code: String,
    val configurationIds: Set<CredentialConfigurationId>
)

class GetPreauthorizedCode(
    private val getAuthorizationSessionByRequestUriOnce: GetAuthorizationSessionByRequestUriOnce,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val metadata: CredentialIssuerMetaData
) {
    suspend operator fun invoke(requestUri: URI): PreAuthorizedCodeData {
        val session = getAuthorizationSessionByRequestUriOnce(requestUri, AccessTokenRequest.PREAUTHORIZED_CLIENTID)
        val newRequestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}")
        storeRequestUriReference(newRequestUri, AccessTokenRequest.PREAUTHORIZED_CLIENTID, session.id)
        val scopeList = session.authRequest.scope.toStringList()
        val configurationIds = metadata.specificCredentialIssuers
            .filter { it.supportedCredential.scope?.value in scopeList }
            .map {
                it.supportedCredential.id
            }
            .toSet()
        return PreAuthorizedCodeData(code = newRequestUri.toString(), configurationIds = configurationIds)
    }
}
