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

import org.apache.wss4j.common.ext.WSPasswordCallback
import javax.security.auth.callback.Callback
import javax.security.auth.callback.CallbackHandler
import javax.security.auth.callback.UnsupportedCallbackException

internal class PasswordCallback(
    private val alias: String? = null,
    private val password: String? = null,
) : CallbackHandler {

    @Throws(UnsupportedCallbackException::class)
    override fun handle(callbacks: Array<Callback>) {
        for (callback in callbacks) {
            if (callback !is WSPasswordCallback) {
                throw UnsupportedCallbackException(callback, "Only WSPasswordCallback is supported.")
            }

            if (callback.identifier != alias) {
                throw IllegalArgumentException("Unknown keystoreAlias: ${callback.identifier}")
            }

            callback.password = password
        }
    }
}
