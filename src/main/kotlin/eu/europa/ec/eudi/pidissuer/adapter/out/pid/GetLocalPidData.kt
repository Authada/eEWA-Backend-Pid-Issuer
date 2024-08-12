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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriRepeatable
import java.net.URI
import java.time.Clock
import java.time.LocalDate
import java.time.Period
import java.time.Year

class GetLocalPidData(
    private val getAuthorizationSessionByRequestUriRepeatable: GetAuthorizationSessionByRequestUriRepeatable,
    private val clock: Clock
) : GetPidData {
    override suspend fun invoke(username: Username): Pair<Pid, PidMetaData>? {
        throw UnsupportedOperationException()
    }

    context (Raise<IssueCredentialError.Unexpected>)
    override suspend operator fun invoke(authorizationContext: AuthorizationContext): Pair<Pid, PidMetaData> {
        val session = getAuthorizationSessionByRequestUriRepeatable(
            URI(authorizationContext.accessToken.value),
            authorizationContext.clientId!!
        )
        val eid = session.eidData
        val gergorianDateOfBirth = eid?.dateOfBirth?.dateValue?.toGregorianCalendar()?.toZonedDateTime()
        val pid = Pid(
            familyName = eid?.familyNames?.let { FamilyName(it) },
            givenName = eid?.givenNames?.let { GivenName(it) },
            birthDate = gergorianDateOfBirth?.toLocalDate(),
            ageOver18 = session.ageVerificationResult,
            ageBirthYear = eid?.dateOfBirth?.dateValue?.year?.let { Year.of(it) },
            ageInYears = gergorianDateOfBirth?.let {
                Period.between(it.toLocalDate(), clock.instant().atZone(it.zone).toLocalDate()).years.toUInt()
            },
            familyNameBirth = eid?.birthName?.let { FamilyName(eid.birthName) },
            givenNameBirth = null,
            birthPlace = eid?.placeOfBirth?.freetextPlace ?: eid?.placeOfBirth?.noPlaceInfo,
            birthCountry = eid?.placeOfBirth?.structuredPlace?.country?.let { IsoCountry(it) },
            birthState = eid?.placeOfBirth?.structuredPlace?.state?.let { State(it) },
            birthCity = eid?.placeOfBirth?.structuredPlace?.city?.let { City(it) },
            residentAddress = eid?.placeOfResidence?.structuredPlace?.let {
                """
                    ${it.street}
                    ${it.zipCode} ${it.city}
                    ${it.country}
                """.trimIndent()
            } ?: eid?.placeOfResidence?.freetextPlace ?: eid?.placeOfResidence?.noPlaceInfo,
            residentStreet = eid?.placeOfResidence?.structuredPlace?.street?.let { Street(it) },
            residentCountry = eid?.placeOfResidence?.structuredPlace?.country?.let { IsoCountry(it) },
            residentState = eid?.placeOfResidence?.structuredPlace?.state?.let { State(it) },
            residentCity = eid?.placeOfResidence?.structuredPlace?.city?.let { City(it) },
            residentPostalCode = eid?.placeOfResidence?.structuredPlace?.zipCode?.let { PostalCode(it) },
            residentHouseNumber = null,
            gender = null,
            nationality = eid?.nationality?.let { Nationality(it) },
            alsoKnownAs = eid?.artisticName
        )
        val pidMeta = PidMetaData(
            issuanceDate = LocalDate.now(),
            expiryDate = eid?.dateOfExpiry?.toGregorianCalendar()?.toZonedDateTime()?.toLocalDate(),
            issuingCountry = eid?.issuingState?.let { IsoCountry(it) },
            issuingAuthority = eid?.issuingState?.let { IssuingAuthority.MemberState(IsoCountry(it)) },
            sourceType = eid?.documentType?.let {
                when (eid.documentType) {
                    "ID" -> "id_card"
                    "AS", "AR", "AF" -> "residence_permit"
                    "UB" -> "eu_citizen_eid_card"
                    else -> "test_id_card"
                }
            }
        )
        return ensureNotNull(pid to pidMeta) { IssueCredentialError.Unexpected("Cannot obtain data") }
    }
}
