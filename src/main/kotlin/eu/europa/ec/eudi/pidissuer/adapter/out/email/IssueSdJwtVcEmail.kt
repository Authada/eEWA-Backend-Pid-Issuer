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
import eu.europa.ec.eudi.pidissuer.domain.CredentialDisplay
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.DisplayName
import eu.europa.ec.eudi.pidissuer.domain.ImageUri
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.sdjwt.HashAlgorithm.SHA_256
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.util.Locale
import java.util.Locale.ENGLISH


internal const val EMAIL_DOCTYPE_SDJWT = "urn:eu.europa.ec.eudi:email"

internal fun emailDocTypeSdjwt(v: Int?): String =
    if (v == null) EMAIL_DOCTYPE_SDJWT
    else "$EMAIL_DOCTYPE_SDJWT:$v"


val emailDisplay = { publicUrl: String ->
    listOf(
        CredentialDisplay(
            name = DisplayName("E-mail address", ENGLISH),
            logo = ImageUri(
                UriComponentsBuilder.fromUriString(publicUrl.removeSuffix("/"))
                    .path("/public/img/email/logo.png")
                    .build().toUri(),
                alternativeText = "Email icon"
            ),
            description = "eEWA Verified Email Prototype",
            backgroundColor = "#bff6ec",
            backgroundImage = ImageUri(
                URI.create("https://authada.de/customerlogos/authada_dark.png"),
                alternativeText = "AUTHADA dark logo"
            ),
            textColor = "#000000"
        ),
    )
}

val EmailSdJwtVcScope: Scope = Scope("${EMAIL_DOCTYPE}_vc_sd_jwt")
val EmailSdJwtVcScopeNew: Scope = Scope("${EMAIL_DOCTYPE_SDJWT}_vc_sd_jwt")

internal object Attributes {
    val IssuanceDate = AttributeDetails(
        name = "iat",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Date of issue"),
    )

    val ExpiryDate = AttributeDetails(
        name = "exp",
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

fun emailSdJwtVcV1(
    issuerSigningKey: IssuerSigningKey,
    credentialIssuerId: CredentialIssuerId,
    docType: SdJwtVcType = emailDocType(1),
    scope: Scope = EmailSdJwtVcScope
): SdJwtVcCredentialConfiguration<EmailData> =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(scope.value),
        docType = docType,
        display = emailDisplay(credentialIssuerId),
        claims = Attributes.emailAttributes,
        scope = scope,
        encode = EncodeEmailInSdJwtVc(
            hashAlgorithm = SHA_256,
            credentialIssuerId = credentialIssuerId,
            issuerSigningKey = issuerSigningKey,
            docType
        ),
        issuerSigningKey = issuerSigningKey,
        issuerId = credentialIssuerId
    )


