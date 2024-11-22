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
package eu.europa.ec.eudi.pidissuer.adapter.out.email

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.adapter.out.GetData
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriRepeatable
import java.net.URI
import java.time.Clock
import java.time.LocalDate

class GetLocalEmailData(
    private val getAuthorizationSessionByRequestUriRepeatable: GetAuthorizationSessionByRequestUriRepeatable,
    private val clock: Clock
) : GetData<EmailData> {
    override suspend fun invoke(username: Username): EmailData {
        throw UnsupportedOperationException()
    }

    context (Raise<IssueCredentialError.Unexpected>)
    override suspend operator fun invoke(authorizationContext: AuthorizationContext): EmailData {
        val session = getAuthorizationSessionByRequestUriRepeatable(
            URI(authorizationContext.accessToken.value),
            authorizationContext.clientId!!
        )
        val email = ensureNotNull(session.email) { IssueCredentialError.Unexpected("Cannot obtain data") }

        return EmailData(
            email = email,
            issuanceDate = LocalDate.now(clock),
            expiryDate = LocalDate.now(clock).plusYears(1)
        )
    }
}
