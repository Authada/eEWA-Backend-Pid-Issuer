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
import eu.europa.ec.eudi.pidissuer.domain.MSO_MDOC_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import eu.europa.ec.eudi.pidissuer.domain.Scope
import java.time.Clock
import java.util.Locale
import kotlin.time.Duration

val PidMsoMdocScope: Scope = Scope("${PID_DOCTYPE}_${MSO_MDOC_FORMAT.value}")

val PidMsoMdocNamespace: MsoNameSpace = pidNameSpace(1)

val GivenNameAttribute = AttributeDetails(
    name = "given_name",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Current First Names"),
    operationSetter = OperationsRequestorType::setGivenNames
)
val FamilyNameAttribute = AttributeDetails(
    name = "family_name",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Current Family Name"),
    operationSetter = OperationsRequestorType::setFamilyNames
)
val BirthDateAttribute = AttributeDetails(
    name = "birth_date",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Date of Birth"),
    operationSetter = OperationsRequestorType::setDateOfBirth
)
val FamilyNameBirthAttribute = AttributeDetails(
    name = "family_name_birth",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
    operationSetter = OperationsRequestorType::setBirthName
)

//val GivenNameBirthAttribute = AttributeDetails(
//    name = "given_name_birth",
//    mandatory = false,
//    display = mapOf(Locale.ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
//)
//val GenderAttribute = AttributeDetails(
//    name = "gender",
//    mandatory = false,
//    display = mapOf(Locale.ENGLISH to "PID User’s gender, using a value as defined in ISO/IEC 5218."),
//)
val AgeOver18Attribute = AttributeDetails(
    name = "age_over_18",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Attesting whether the PID User is currently an adult (true) or a minor (false)."),
    operationSetter = OperationsRequestorType::setAgeVerification
)
val AgeBirthYearAttribute = AttributeDetails(
    name = "age_birth_year",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The year when the PID User was born."),
    operationSetter = OperationsRequestorType::setDateOfBirth
)
val AgeInYearsAttribute = AttributeDetails(
    name = "age_in_years",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The current age of the PID User in years."),
    operationSetter = OperationsRequestorType::setDateOfBirth
)
val NationalityAttribute = AttributeDetails(
    name = "nationality",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code, representing the nationality of the PID User."),
    operationSetter = OperationsRequestorType::setNationality
)
val IssuanceDateAttribute = AttributeDetails(
    name = "issuance_date",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Date (and possibly time) when the PID was issued."),
)
val ExpiryDateAttribute = AttributeDetails(
    name = "expiry_date",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Date (and possibly time) when the PID will expire."),
    operationSetter = OperationsRequestorType::setDateOfExpiry
)
val IssuingAuthorityAttribute = AttributeDetails(
    name = "issuing_authority",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "Name of the administrative authority that has issued this PID instance, " +
                "or the ISO 3166 Alpha-2 country code of the respective Member State if there is " +
                "no separate authority authorized to issue PIDs.",
    ),
    operationSetter = OperationsRequestorType::setIssuingState
)
val BirthPlaceAttribute = AttributeDetails(
    name = "birth_place",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The country, state, and city where the PID User was born."),
    operationSetter = OperationsRequestorType::setPlaceOfBirth
)
val BirthCountryAttribute = AttributeDetails(
    name = "birth_country",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The country where the PID User was born, as an Alpha-2 country code."),
    operationSetter = OperationsRequestorType::setPlaceOfBirth
)
val BirthStateAttribute = AttributeDetails(
    name = "birth_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born. "),
    operationSetter = OperationsRequestorType::setPlaceOfBirth
)
val BirthCityAttribute = AttributeDetails(
    name = "birth_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User was born. "),
    operationSetter = OperationsRequestorType::setPlaceOfBirth
)
val ResidenceAddressAttribute = AttributeDetails(
    name = "resident_address",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "The full address of the place where the PID User currently resides and/or " +
                "can be contacted (street name, house number, city etc.).",
    ),
    operationSetter = OperationsRequestorType::setPlaceOfResidence
)
val ResidenceCountryAttribute = AttributeDetails(
    name = "resident_country",
    mandatory = false,
    display = mapOf(
        Locale.ENGLISH to "he country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1.",
    ),
    operationSetter = OperationsRequestorType::setPlaceOfResidence
)
val ResidenceStateAttribute = AttributeDetails(
    name = "resident_state",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User currently resides"),
    operationSetter = OperationsRequestorType::setPlaceOfResidence
)
val ResidenceCityAttribute = AttributeDetails(
    name = "resident_city",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User currently resides."),
    operationSetter = OperationsRequestorType::setPlaceOfResidence
)
val ResidencePostalCodeAttribute = AttributeDetails(
    name = "resident_postal_code",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Postal code of the place where the PID User currently resides."),
    operationSetter = OperationsRequestorType::setPlaceOfResidence
)
val ResidenceStreetAttribute = AttributeDetails(
    name = "resident_street",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "The name of the street where the PID User currently resides"),
    operationSetter = OperationsRequestorType::setPlaceOfResidence
)

//val ResidenceHouseNumberAttribute = AttributeDetails(
//    name = "resident_house_number",
//    mandatory = false,
//    display = mapOf(Locale.ENGLISH to "The house number where the PID User currently resides, including any affix or suffix."),
//)
//val DocumentNumberAttribute = AttributeDetails(
//    name = "document_number",
//    mandatory = false,
//    display = mapOf(Locale.ENGLISH to "A number for the PID, assigned by the PID Provider."),
//)
//val AdministrativeNumberAttribute = AttributeDetails(
//    name = "document_number",
//    mandatory = false,
//    display = mapOf(Locale.ENGLISH to "A number for the PID, assigned by the PID Provider."),
//)
val IssuingCountryAttribute = AttributeDetails(
    name = "issuing_country",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider’s country or territory."),
    operationSetter = OperationsRequestorType::setIssuingState
)

val SourceDocumentType = AttributeDetails(
    name = "source_document_type",
    mandatory = false,
    display = mapOf(Locale.ENGLISH to "Source document type"),
    operationSetter = OperationsRequestorType::setDocumentType
)

//val IssuingJurisdictionAttribute = AttributeDetails(
//    name = "issuing_jurisdiction",
//    mandatory = false,
//    display = mapOf(
//        Locale.ENGLISH to "Country subdivision code of the jurisdiction that issued the PID, " +
//            "as defined in ISO 3166-2:2020, Clause 8. The first part of the code SHALL be the same " +
//            "as the value for issuing_country.",
//    ),
//)
val pidMdocAttributes = PidMsoMdocNamespace to listOf(
    FamilyNameAttribute,
    GivenNameAttribute,
    BirthDateAttribute,
    AgeOver18Attribute,
    AgeBirthYearAttribute,
    AgeInYearsAttribute,
    FamilyNameBirthAttribute,
//    GivenNameBirthAttribute,
    BirthPlaceAttribute,
    BirthCountryAttribute,
    BirthStateAttribute,
    BirthCityAttribute,
    ResidenceAddressAttribute,
    ResidenceCountryAttribute,
    ResidenceStateAttribute,
    ResidenceCityAttribute,
    ResidencePostalCodeAttribute,
    ResidenceStreetAttribute,
//    ResidenceHouseNumberAttribute,
//    GenderAttribute,
    NationalityAttribute,
    IssuanceDateAttribute,
    ExpiryDateAttribute,
    IssuingAuthorityAttribute,
//    DocumentNumberAttribute,
//    AdministrativeNumberAttribute,
    IssuingCountryAttribute,
//    IssuingJurisdictionAttribute,
    SourceDocumentType,
)

fun pidMsoMdocV1(
    issuerSigningKey: IssuerSigningKey,
    clock: Clock,
    validityDuration: Duration,
    issuerId: CredentialIssuerId
): MsoMdocCredentialConfiguration<Pid> =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(PidMsoMdocScope.value),
        docType = pidDocType(1),
        display = pidDisplay,
        msoClaims = mapOf(pidMdocAttributes),
        scope = PidMsoMdocScope,
        encode = DefaultEncodePidInCbor(clock, issuerSigningKey, validityDuration),
        issuerId = issuerId,
    )

//
// Meta
//

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)
