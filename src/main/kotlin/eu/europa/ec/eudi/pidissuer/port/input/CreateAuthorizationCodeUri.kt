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

import com.nimbusds.oauth2.sdk.id.State
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

class CreateAuthorizationCodeUri {
    operator fun invoke(redirectUri: URI, code: String, state: State?): URI = UriComponentsBuilder
        .fromUriString(redirectUri.toString())
        .queryParam("code", code)
        .apply {
            state?.let {
                queryParam("state", it.value)
            }
        }
        .build()
        .toUri()

}
