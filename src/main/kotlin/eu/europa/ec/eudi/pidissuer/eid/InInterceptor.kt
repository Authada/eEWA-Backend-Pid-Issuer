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
package eu.europa.ec.eudi.pidissuer.eid

import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor
import org.apache.wss4j.common.ConfigurationConstants
import org.apache.wss4j.common.crypto.Merlin


open class InInterceptor(merlinInstance: Merlin) : WSS4JInInterceptor(mapOf(
        ConfigurationConstants.ACTION to TIMESTAMP_SIGNATURE_ACTION,
        ConfigurationConstants.SIG_PROP_REF_ID to MERLIN_INSTANCE_KEY,
        MERLIN_INSTANCE_KEY to merlinInstance,
        ConfigurationConstants.SIG_KEY_ID to ISSUER_SERIAL
)) {

    companion object {
        private const val MERLIN_INSTANCE_KEY = "merlinInstance"
        private const val TIMESTAMP_SIGNATURE_ACTION = "Timestamp Signature"
        private const val ISSUER_SERIAL = "IssuerSerial"
    }
}
