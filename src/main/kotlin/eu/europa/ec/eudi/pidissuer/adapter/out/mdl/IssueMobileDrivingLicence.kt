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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialDisplay
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.DisplayName
import eu.europa.ec.eudi.pidissuer.domain.ImageUri
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import eu.europa.ec.eudi.pidissuer.domain.Scope
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.time.Clock
import java.util.Locale
import kotlin.time.Duration

val MobileDrivingLicenceV1Scope: Scope = Scope(mdlDocType(1u))

val MobileDrivingLicenceV1Namespace: MsoNameSpace = mdlNamespace(1u)

val FamilyNameAttribute = AttributeDetails(
    name = "family_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Last name, surname, or primary identifier of the mDL holder."),
)
val GivenNameAttribute = AttributeDetails(
    name = "given_name",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "First name(s), other name(s), or secondary identifier, of the mDL holder."),
)
val BirthDateAttribute = AttributeDetails(
    name = "birth_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Day, month and year on which the mDL holder was born."),
)
val IssueDateAttribute = AttributeDetails(
    name = "issue_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date when mDL was issued."),
)
val ExpiryDateAttribute = AttributeDetails(
    name = "expiry_date",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Date when mDL expires."),
)
val PortraitAttribute = AttributeDetails(
    name = "portrait",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "A reproduction of the mDL holder’s portrait."),
)
val PortraitCaptureDateAttribute = AttributeDetails(
    name = "portrait_capture_date",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Date when portrait was taken."),
)
val SexAttribute = AttributeDetails(
    name = "sex",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "mDL holder’s sex using values as defined in ISO/IEC 5218."),
)
val HeightAttribute = AttributeDetails(
    name = "height",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "mDL holder’s height in centimetres."),
)
val WeightAttribute = AttributeDetails(
    name = "weight",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "mDL holder’s weight in kilograms."),
)
val HairColourAttribute = AttributeDetails(
    name = "hair_colour",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "mDL holder’s hair colour."),
)
val BirthPlaceAttribute = AttributeDetails(
    name = "birth_place",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Country and municipality or state/province where the mDL holder was born."),
)
val ResidentAddressAttribute = AttributeDetails(
    name = "resident_address",
    mandatory = false,
    display = buildMap {
        put(
            Locale.ENGLISH,
            "The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).",
        )
    },
)
val EyeColourAttribute = AttributeDetails(
    name = "eye_colour",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "mDL holder’s eye colour."),
)
val ResidentCityAttribute = AttributeDetails(
    name = "resident_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The city where the mDL holder lives."),
)
val ResidentStateAttribute = AttributeDetails(
    name = "resident_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state/province/district where the mDL holder lives."),
)
val ResidentPostalCodeAttribute = AttributeDetails(
    name = "resident_postal_code",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The postal code of the mDL holder."),
)
val ResidentCountryAttribute = AttributeDetails(
    name = "resident_country",
    mandatory = false,
    display = buildMap {
        put(
            Locale.ENGLISH,
            "The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1.",
        )
    },
)
val AgeInYearsAttribute = AttributeDetails(
    name = "age_in_years",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The age of the mDL holder."),
)
val AgeBirthYearAttribute = AttributeDetails(
    name = "age_birth_year",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The year when the mDL holder was born."),
)
val AgeOver18Attribute = AttributeDetails(
    name = "age_over_18",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Whether the mDL holder is over 18 years old."),
)
val AgeOver21Attribute = AttributeDetails(
    name = "age_over_21",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Whether the mDL holder is over 21 years old."),
)
val NationalityAttribute = AttributeDetails(
    name = "nationality",
    mandatory = false,
    display = buildMap {
        put(
            Locale.ENGLISH,
            "Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1.",
        )
    },
)
val FamilyNameNationalCharacterAttribute = AttributeDetails(
    name = "family_name_national_character",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The family name of the mDL holder using full UTF-8 character set."),
)
val GivenNameNationalCharacterAttribute = AttributeDetails(
    name = "given_name_national_character",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The given name of the mDL holder using full UTF-8 character set."),
)
val SignatureUsualMarkAttribute = AttributeDetails(
    name = "signature_usual_mark",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Image of the signature or usual mark of the mDL holder."),
)
val IssuingCountryAttribute = AttributeDetails(
    name = "issuing_country",
    mandatory = true,
    display = buildMap {
        put(
            Locale.ENGLISH,
            "Alpha-2 country code, as defined in ISO 3166-1 of the issuing authority’s country or territory.",
        )
    },
)
val IssuingAuthorityAttribute = AttributeDetails(
    name = "issuing_authority",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Issuing authority name."),
)
val IssuingCountryDistinguishingSignAttribute = AttributeDetails(
    name = "un_distinguishing_sign",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F."),
)
val IssuingJurisdictionAttribute = AttributeDetails(
    name = "issuing_jurisdiction",
    mandatory = false,
    display = buildMap {
        put(
            Locale.ENGLISH,
            "Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8.",
        )
    },
)
val DocumentNumberAttribute = AttributeDetails(
    name = "document_number",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "The number assigned or calculated by the issuing authority."),
)
val AdministrativeNumberAttribute = AttributeDetails(
    name = "administrative_number",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "An audit control number assigned by the issuing authority."),
)
val DrivingPrivilegesAttribute = AttributeDetails(
    name = "driving_privileges",
    mandatory = true,
    display = mapOf(Locale.ENGLISH to "Driving privileges of the mDL holder."),
)
val MobileDrivingLicenceV1Attributes: List<AttributeDetails> = listOf(
    FamilyNameAttribute,
    GivenNameAttribute,
    BirthDateAttribute,
    IssueDateAttribute,
    ExpiryDateAttribute,
    IssuingCountryAttribute,
    IssuingAuthorityAttribute,
    DocumentNumberAttribute,
    PortraitAttribute,
    DrivingPrivilegesAttribute,
    IssuingCountryDistinguishingSignAttribute,
    AdministrativeNumberAttribute,
    SexAttribute,
    HeightAttribute,
    WeightAttribute,
    EyeColourAttribute,
    HairColourAttribute,
    BirthPlaceAttribute,
    ResidentAddressAttribute,
    PortraitCaptureDateAttribute,
    AgeInYearsAttribute,
    AgeBirthYearAttribute,
    AgeOver18Attribute,
    AgeOver21Attribute,
    IssuingJurisdictionAttribute,
    NationalityAttribute,
    ResidentCityAttribute,
    ResidentStateAttribute,
    ResidentPostalCodeAttribute,
    ResidentCountryAttribute,
    FamilyNameNationalCharacterAttribute,
    GivenNameNationalCharacterAttribute,
    SignatureUsualMarkAttribute,
)

val MobileDrivingLicenceDisplay = { publicUrl: String ->
    listOf(
        CredentialDisplay(
            name = DisplayName("Mobile Driving Licence", Locale.ENGLISH),
            logo = ImageUri(
                UriComponentsBuilder.fromUriString(publicUrl.removeSuffix("/"))
                    .path("/public/img/mdl/logo.png")
                    .build().toUri(),
                alternativeText = "Driver license icon"
            ),
            description = "eEWA Mobile Driving License Prototype",
            backgroundColor = "#f4f4f4",
            backgroundImage = ImageUri(
                URI.create("https://authada.de/customerlogos/authada_dark.png"),
                alternativeText = "AUTHADA dark logo"
            ),
            textColor = "#000000"
        ),
    )
}

fun mobileDrivingLicenceV1(
    issuerSigningKey: IssuerSigningKey,
    clock: Clock,
    validityDuration: Duration,
    issuerId: CredentialIssuerId
): MsoMdocCredentialConfiguration<MobileDrivingLicence> =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(MobileDrivingLicenceV1Scope.value),
        docType = mdlDocType(1u),
        display = MobileDrivingLicenceDisplay(issuerId),
        msoClaims = mapOf(MobileDrivingLicenceV1Namespace to MobileDrivingLicenceV1Attributes),
        scope = MobileDrivingLicenceV1Scope,
        encode = DefaultEncodeMobileDrivingLicenceInCbor(clock, issuerSigningKey, validityDuration),
        issuerId = issuerId,
    )
