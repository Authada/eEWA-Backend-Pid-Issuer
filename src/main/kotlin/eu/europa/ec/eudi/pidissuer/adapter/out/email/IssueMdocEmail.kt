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

import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.Scope
import java.time.Clock
import java.util.Locale
import kotlin.time.Duration

internal const val EMAIL_DOCTYPE = "eu.europa.ec.eudi.email"

internal fun emailDocType(v: Int?): String =
    if (v == null) EMAIL_DOCTYPE
    else "$EMAIL_DOCTYPE.$v"

val EmailMdocScope: Scope = Scope("${EMAIL_DOCTYPE}_mso_mdoc")

internal object MdocAttributes {
    val IssuanceDate = AttributeDetails(
        name = "issuance_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Date of issue"),
    )

    val ExpiryDate = AttributeDetails(
        name = "expiry_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Valid until"),
    )

    val EmailAttribute = AttributeDetails(
        name = "email",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "E-mail address"),
    )

    val emailAttributes = listOf(
        EmailAttribute,
        IssuanceDate,
        ExpiryDate,
    )
}

fun emailMsoMdocV1(
    issuerSigningKey: IssuerSigningKey,
    clock: Clock,
    validityDuration: Duration,
    issuerId: CredentialIssuerId
): MsoMdocCredentialConfiguration<EmailData> =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(EmailMdocScope.value),
        docType = emailDocType(1),
        display = emailDisplay(issuerId),
        msoClaims = mapOf(emailDocType(1) to MdocAttributes.emailAttributes),
        scope = EmailMdocScope,
        encode = DefaultEncodeEmailInCbor(
            issuerSigningKey = issuerSigningKey,
            clock = clock,
            validityDuration = validityDuration
        ),
        issuerId = issuerId
    )
