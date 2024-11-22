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

import eu.europa.ec.eudi.pidissuer.adapter.input.web.TokenApi
import org.slf4j.LoggerFactory

class PreAuthorizedCodeGrant(params: Map<String, List<String>>) : AuthorizationGrant(GrantType.PRE_AUTHORIZED_CODE) {

    val preAuthorizedCode: String = requireNotNull((params[PRE_AUTHORIZED_CODE_PARAM] ?: emptyList()).singleOrNull()) {
        "Missing $PRE_AUTHORIZED_CODE_PARAM param"
    }

    val txCode: String? = params[TX_CODE_PARAM]?.singleOrNull()

    override fun toParameters(): MutableMap<String, MutableList<String>> = buildMap {
        PRE_AUTHORIZED_CODE_PARAM to mutableListOf(preAuthorizedCode)
        txCode?.let {
            put(TX_CODE_PARAM, mutableListOf(txCode))
        }
    }.toMutableMap()

    companion object {
        const val PRE_AUTHORIZED_CODE_PARAM = "pre-authorized_code"
        const val TX_CODE_PARAM = "tx_code"
    }
}
