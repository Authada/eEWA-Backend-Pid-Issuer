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


internal const val MSISDN_DOCTYPE = "eu.europa.ec.eudi.msisdn"

internal fun msisdnDocType(v: Int?): String =
    if (v == null) MSISDN_DOCTYPE
    else "$MSISDN_DOCTYPE.$v"

internal const val MSISDN_DOCTYPE_SDJWT = "urn:eu.europa.ec.eudi:msisdn"

internal fun msisdnDocTypeSdjwt(v: Int?): String =
    if (v == null) MSISDN_DOCTYPE_SDJWT
    else "$MSISDN_DOCTYPE_SDJWT:$v"

val msisdnDisplay = { publicUrl: String ->
    listOf(
        CredentialDisplay(
            name = DisplayName("Phone number", ENGLISH),
            logo = ImageUri(
                UriComponentsBuilder.fromUriString(publicUrl.removeSuffix("/"))
                    .path("/public/img/msisdn/logo.png")
                    .build().toUri(),
                alternativeText = "MSISDN icon"
            ),
            description = "eEWA MSISDN Attestation Prototype",
            backgroundColor = "#ffe0bf",
            backgroundImage = ImageUri(
                URI.create("https://authada.de/customerlogos/authada_dark.png"),
                alternativeText = "AUTHADA dark logo"
            ),
            textColor = "#000000"
        ),
    )
}

val MsisdnSdJwtVcScope: Scope = Scope("${MSISDN_DOCTYPE}_vc_sd_jwt")
val MsisdnSdJwtVcScopeNew: Scope = Scope("${MSISDN_DOCTYPE_SDJWT}_vc_sd_jwt")

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

    val PhoneNumberAttribute = AttributeDetails(
        name = "phone_number",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Phone number"),
    )

    val RegisteredFamilyName = AttributeDetails(
        name = "registered_family_name",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Current last name(s) or surname(s)"),
    )
    val RegisteredGivenName = AttributeDetails(
        name = "registered_given_name",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Current first name(s) including middle name(s)"),
    )

    val ContractOwner = AttributeDetails(
        name = "contract_owner",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Current first name(s) including middle name(s)"),
    )
    val EndUser = AttributeDetails(
        name = "end_user",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "If the wallet holder is the end user of the MSISDN"),
    )
    val MobileOperator = AttributeDetails(
        name = "mobile_operator",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "The MNO for issuing the MSIDN"),
    )

    val IssuingOrganization = AttributeDetails(
        name = "issuing_organization",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "The MNO attributes"),
    )

    val VerificationDate = AttributeDetails(
        name = "verification_date",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "The date the MSISDN was verified"),
    )

    val VerificationMethodInformation = AttributeDetails(
        name = "verification_method_Information",
        mandatory = true,
        display = mapOf(Locale.ENGLISH to "Corresponding to the VC data model"),
    )

    val msisdnAttributes = listOf(
        PhoneNumberAttribute,
        IssuanceDate,
        ExpiryDate,
        RegisteredGivenName,
        RegisteredFamilyName,
        EndUser,
        VerificationMethodInformation,
        VerificationDate,
        IssuingOrganization,
        MobileOperator,
        ContractOwner
    )
}

fun msisdnSdJwtVcV1(
    credentialIssuerId: CredentialIssuerId,
    issuerSigningKey: IssuerSigningKey,
    docType: SdJwtVcType = msisdnDocType(1),
    scope: Scope = MsisdnSdJwtVcScope
): SdJwtVcCredentialConfiguration<MsisdnData> =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(scope.value),
        docType = docType,
        display = msisdnDisplay(credentialIssuerId),
        claims = Attributes.msisdnAttributes,
        scope = scope,
        encode = EncodeMsisdnInSdJwtVc(credentialIssuerId, SHA_256, issuerSigningKey, docType),
        issuerSigningKey = issuerSigningKey,
        issuerId = credentialIssuerId
    )

