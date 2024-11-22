/*
 * Copyright (c) 2023 European Commission
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
 *
 * Modified by AUTHADA GmbH
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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import de.bund.bsi.eid.OperationsRequestorType
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.sdjwt.HashAlgorithm.SHA_256
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.util.Locale

val PidSdJwtVcScope: Scope = Scope("${PID_DOCTYPE}_vc_sd_jwt")
val PidSdJwtVcScopeNew: Scope = Scope("${PID_DOCTYPE_SDJWTVC}_vc_sd_jwt")
val PidSdJwtVcScopeNew2: Scope = Scope("${PID_DOCTYPE_SDJWTVC_NEW}_vc_sd_jwt")

internal object Attributes {

    val GivenName = AttributeDetails(
        name = "given_name",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Current First Names"),
        operationSetter = OperationsRequestorType::setGivenNames
    )

    val FamilyName: AttributeDetails by lazy {
        AttributeDetails(
            name = "family_name",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Current Family Name"),
            operationSetter = OperationsRequestorType::setFamilyNames
        )
    }

    val BirthDateYear = AttributeDetails(
        name = "age_birth_year",
        mandatory = false,
        operationSetter = OperationsRequestorType::setDateOfBirth
    )

    val AgeEqualOrOver = AttributeDetails(
        name = "age_equal_or_over",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age attestations"),
        operationSetter = OperationsRequestorType::setAgeVerification
    )

    val AgeInYears = AttributeDetails(
        name = "age_in_years",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The subject’s current age in years."),
        operationSetter = OperationsRequestorType::setDateOfBirth
    )

    val IssuanceDate = AttributeDetails(
        name = "iat",
        mandatory = false,
    )

    val ExpiryDate = AttributeDetails(
        name = "exp",
        mandatory = false,
        operationSetter = OperationsRequestorType::setDateOfExpiry
    )

    val IssuingCountry = AttributeDetails(
        name = "issuing_country",
        mandatory = false,
        operationSetter = OperationsRequestorType::setIssuingState
    )
    val IssuingAuthority = AttributeDetails(
        name = "issuing_authority",
        mandatory = false,
        operationSetter = OperationsRequestorType::setIssuingState
    )
    val BirthDate = AttributeDetails(
        name = "birthdate",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Date of Birth"),
        operationSetter = OperationsRequestorType::setDateOfBirth
    )


    val BirthPlace: AttributeDetails by lazy {
        AttributeDetails(
            name = "place_of_birth",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Place of Birth"),
            operationSetter = OperationsRequestorType::setPlaceOfBirth
        )
    }


    val Address: AttributeDetails by lazy {
        AttributeDetails(
            name = "address",
            mandatory = false,
            display = mapOf(
                Locale.ENGLISH to "Resident street_address, country, region, locality and postal_code",
            ),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }

    val Nationality: AttributeDetails by lazy {
        AttributeDetails(
            name = "nationalities",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Nationalities"),
            operationSetter = OperationsRequestorType::setNationality
        )
    }
    val SourceDocumentType: AttributeDetails by lazy {
        AttributeDetails(
            name = "source_document_type",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Source document type"),
            operationSetter = OperationsRequestorType::setDocumentType
        )
    }

    val FamiltyNameBirth: AttributeDetails by lazy {
        AttributeDetails(
            name = "birth_family_name",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
            operationSetter = OperationsRequestorType::setBirthName
        )
    }


    val AlsoKnownAs: AttributeDetails by lazy {
        AttributeDetails(
            name = "also_known_as",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Artistic name"),
            operationSetter = OperationsRequestorType::setArtisticName
        )
    }

    val pidAttributes = listOf(
        FamilyName,
        GivenName,
        BirthDate,
        AgeEqualOrOver,
        AgeInYears,
        IssuanceDate,
        BirthDateYear,
        Nationality,
        FamiltyNameBirth,
        BirthPlace,
        ExpiryDate,
        IssuingCountry,
        IssuingAuthority,
        SourceDocumentType,
        Address,
        AlsoKnownAs
    )
}

fun pidSdJwtVcV1(
    issuerSigningKey: IssuerSigningKey,
    issuerId: CredentialIssuerId,
    clock: Clock,
    calcNotUseBefore: TimeDependant<Instant>?,
    docType: SdJwtVcType = pidDocType(1),
    scope: Scope = PidSdJwtVcScope
): SdJwtVcCredentialConfiguration<Pid> =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(scope.value),
        docType = docType,
        display = pidDisplay,
        claims = Attributes.pidAttributes,
        scope = scope,
        issuerId = issuerId,
        issuerSigningKey = issuerSigningKey,
        encode = EncodePidInSdJwtVc(issuerId, clock, SHA_256, issuerSigningKey, calcNotUseBefore, docType)
    )

typealias TimeDependant<F> = (ZonedDateTime) -> F
