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

import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.Encode
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.MsoMdocAuthenticatedChannelSigner
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.MsoMdocSigner
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import kotlin.time.Duration

internal class DefaultEncodePidInCbor(
    clock: Clock,
    issuerSigningKey:
    IssuerSigningKey,
    validityDuration: Duration,
) : Encode<Pid> {

    private val signer = MsoMdocSigner<Pid>(
        clock = clock,
        issuerSigningKey = issuerSigningKey,
        validityDuration = validityDuration,
        docType = pidDocType(1),
    ) { pid ->
        addItemsToSign(pid)
    }

    private val authenticatedChannelSigner = MsoMdocAuthenticatedChannelSigner<Pid>(
        clock = clock,
        issuerSigningKey = issuerSigningKey,
        validityDuration = validityDuration,
        docType = pidDocType(1),
    ) { pid ->
        addItemsToSign(pid)
    }

    context(Raise<IssueCredentialError>)
    override suspend operator fun invoke(
        data: Pid,
        holderKey: JWK,
        verifierKA: VerifierKA?
    ): String = verifierKA?.let {
        authenticatedChannelSigner.sign(data, holderKey.toECKey(), it)
    } ?: run { signer.sign(data, holderKey.toECKey()) }

}

private fun MDocBuilder.addItemsToSign(pid: Pid) {
    pid.givenName?.let { addItemToSign(GivenNameAttribute, pid.givenName.value.toDataElement()) }
    pid.familyName?.let { addItemToSign(FamilyNameAttribute, pid.familyName.value.toDataElement()) }
    pid.birthDate?.let { addItemToSign(BirthDateAttribute, pid.birthDate.toKotlinLocalDate().toDataElement()) }
    pid.familyNameBirth?.let { addItemToSign(FamilyNameBirthAttribute, it.value.toDataElement()) }
//    pid.givenNameBirth?.let { addItemToSign(GivenNameBirthAttribute, it.value.toDataElement()) }
//    pid.gender?.let { addItemToSign(GenderAttribute, it.value.toDataElement()) }
    pid.nationality?.let { addItemToSign(NationalityAttribute, it.value.toDataElement()) }
    pid.ageOver18?.let { addItemToSign(AgeOver18Attribute, it.toDataElement()) }
    pid.ageBirthYear?.let { addItemToSign(AgeBirthYearAttribute, it.value.toDataElement()) }
    pid.ageInYears?.let { addItemToSign(AgeInYearsAttribute, it.toDataElement()) }
    pid.birthPlace?.let { addItemToSign(BirthPlaceAttribute, it.toDataElement()) }
    pid.birthCountry?.let { addItemToSign(BirthCountryAttribute, it.value.toDataElement()) }
    pid.birthState?.let { addItemToSign(BirthStateAttribute, it.value.toDataElement()) }
    pid.birthCity?.let { addItemToSign(BirthCityAttribute, it.value.toDataElement()) }
    pid.residentAddress?.let { addItemToSign(ResidenceAddressAttribute, it.toDataElement()) }
    pid.residentCountry?.let { addItemToSign(ResidenceCountryAttribute, it.value.toDataElement()) }
    pid.residentState?.let { addItemToSign(ResidenceStateAttribute, it.value.toDataElement()) }
    pid.residentCity?.let { addItemToSign(ResidenceCityAttribute, it.value.toDataElement()) }
    pid.residentPostalCode?.let { addItemToSign(ResidencePostalCodeAttribute, it.value.toDataElement()) }
    pid.residentStreet?.let { addItemToSign(ResidenceStreetAttribute, it.value.toDataElement()) }
//    pid.residentHouseNumber?.let { addItemToSign(ResidenceHouseNumberAttribute, it.toDataElement()) }
    addItemsToSign(pid.metaData)
}

private fun MDocBuilder.addItemsToSign(metaData: PidMetaData) {
//    addItemToSign(IssuanceDateAttribute, metaData.issuanceDate.toKotlinLocalDate().toDataElement())
    metaData.expiryDate?.let {
        addItemToSign(
            ExpiryDateAttribute,
            metaData.expiryDate.toKotlinLocalDate().toDataElement()
        )
    }
    when (val issuingAuthority = metaData.issuingAuthority) {
        is IssuingAuthority.MemberState -> addItemToSign(
            IssuingAuthorityAttribute,
            issuingAuthority.code.value.toDataElement()
        )

        is IssuingAuthority.AdministrativeAuthority ->
            addItemToSign(IssuingAuthorityAttribute, issuingAuthority.value.toDataElement())

        null -> {
            //Do nothing
        }
    }
//    metaData.documentNumber?.let { addItemToSign(DocumentNumberAttribute, it.value.toDataElement()) }
//    metaData.administrativeNumber?.let { addItemToSign(AdministrativeNumberAttribute, it.value.toDataElement()) }
    metaData.issuingCountry?.let {
        addItemToSign(
            IssuingCountryAttribute,
            metaData.issuingCountry.value.toDataElement()
        )
    }
    metaData.sourceType?.let { addItemToSign(SourceDocumentType, it.toDataElement()) }
    metaData.issuanceDate?.let {
        addItemToSign(
            IssuanceDateAttribute,
            metaData.issuanceDate.toKotlinLocalDate().toDataElement()
        )
    }
//    metaData.issuingJurisdiction?.let { addItemToSign(IssuingJurisdictionAttribute, it.toDataElement()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement) {
    addItemToSign(PidMsoMdocNamespace, attr.name, value)
}
