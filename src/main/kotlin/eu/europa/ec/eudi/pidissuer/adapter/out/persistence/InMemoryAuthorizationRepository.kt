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
package eu.europa.ec.eudi.pidissuer.adapter.out.persistence

import eu.europa.ec.eudi.pidissuer.domain.AuthorizationSession
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequest.AccessTokenMetadata
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAccessTokenMetadataByToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSession
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriRepeatable
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreAccessTokenMetaByToken
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreAuthorizationSession
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import java.net.URI
import java.util.UUID

class InMemoryAuthorizationRepository {
    private val idAuthorizationSessionMap = mutableMapOf<UUID, AuthorizationSession>()
    private val requestUriReference = mutableMapOf<Pair<URI, String>, UUID>()
    private val authorizationPrincipalReference = mutableMapOf<String, AccessTokenMetadata>()


    val GetAuthorizationSession = GetAuthorizationSession {
        idAuthorizationSessionMap[it]!!
    }

    val StoreAuthorizationSession = StoreAuthorizationSession {
        idAuthorizationSessionMap[it.id] = it
    }

    val StoreRequestUriReference = StoreRequestUriReference { uri, clientId, uuid ->
        requestUriReference[Pair(uri, clientId)] = uuid
    }

    val GetAuthorizationSessionByRequestUriOnce = GetAuthorizationSessionByRequestUriOnce { requestUri, clientId ->
        idAuthorizationSessionMap[requestUriReference.remove(Pair(requestUri, clientId))!!]!!
    }

    val GetAuthorizationSessionByRequestUriRepeatable = GetAuthorizationSessionByRequestUriRepeatable { requestUri, clientId ->
        idAuthorizationSessionMap[requestUriReference[Pair(requestUri, clientId)]!!]!!
    }

    val GetAccessTokenMetadataByToken = GetAccessTokenMetadataByToken {
        authorizationPrincipalReference[it]!!
    }

    val StoreAccessTokenMetadataByToken = StoreAccessTokenMetaByToken { token, metadata ->
        authorizationPrincipalReference[token] = metadata
    }
}
