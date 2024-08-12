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

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import de.bund.bsi.eid.OperationsRequestorType
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIdentifier
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse
import eu.europa.ec.eudi.pidissuer.domain.CryptographicBindingMethod
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.domain.ProofType
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime
import java.util.Locale

val PidSdJwtVcScope: Scope = Scope("${PID_DOCTYPE}_vc_sd_jwt")


interface IsAttribute {
    val attribute: AttributeDetails
}

internal object Attributes {

    val BirthDateYear = AttributeDetails(
        name = "age_birth_year",
        mandatory = false,
        operationSetter = OperationsRequestorType::setDateOfBirth
    )
    val AgeEqualOrOver = AttributeDetails(
        name = "age_equal_or_over",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Age attestations"),
        operationSetter = OperationsRequestorType::setDateOfBirth
    )
    val AgeOver18 = AttributeDetails(
        name = "age_over_18",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Adult or minor"),
        operationSetter = OperationsRequestorType::setAgeVerification
    )

    val AgeInYears = AttributeDetails(
        name = "age_in_years",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The subject’s current age in years."),
        operationSetter = OperationsRequestorType::setDateOfBirth
    )

    val IssuanceDate = AttributeDetails(
        name = "issuance_date",
        mandatory = false,
    )

    val ExpiryDate = AttributeDetails(
        name = "expiry_date",
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

    val FamilyName: AttributeDetails by lazy {
        AttributeDetails(
            name = "family_name",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Current Family Name"),
            operationSetter = OperationsRequestorType::setFamilyNames
        )
    }

    val GivenName = AttributeDetails(
        name = "given_name",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Current First Names"),
        operationSetter = OperationsRequestorType::setGivenNames
    )

    val BirthDate = AttributeDetails(
        name = "birth_date",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Date of Birth"),
        operationSetter = OperationsRequestorType::setDateOfBirth
    )

    val Gender: AttributeDetails by lazy {
        AttributeDetails(
            name = "gender",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "PID User’s gender, using a value as defined in ISO/IEC 5218."),
        )
    }

    val BirthPlace: AttributeDetails by lazy {
        AttributeDetails(
            name = "birth_place",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Place of Birth"),
            operationSetter = OperationsRequestorType::setPlaceOfBirth
        )
    }

    val BirthCountry: AttributeDetails by lazy {
        AttributeDetails(
            name = "birth_country",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Country of Birth"),
            operationSetter = OperationsRequestorType::setPlaceOfBirth
        )
    }

    val BirthState: AttributeDetails by lazy {
        AttributeDetails(
            name = "birth_state",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "State of Birth"),
            operationSetter = OperationsRequestorType::setPlaceOfBirth
        )
    }

    val BirthCity: AttributeDetails by lazy {
        AttributeDetails(
            name = "birth_city",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "City of Birth"),
            operationSetter = OperationsRequestorType::setPlaceOfBirth
        )
    }

    val ResidentAddress: AttributeDetails by lazy {
        AttributeDetails(
            name = "resident_address",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Residence address"),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }

    val ResidentCountry: AttributeDetails by lazy {
        AttributeDetails(
            name = "resident_country",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Residence country"),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }

    val ResidentState: AttributeDetails by lazy {
        AttributeDetails(
            name = "resident_state",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Residence state"),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }

    val ResidentCity: AttributeDetails by lazy {
        AttributeDetails(
            name = "resident_city",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Residence city"),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }

    val ResidentPostalCode: AttributeDetails by lazy {
        AttributeDetails(
            name = "resident_postal_code",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Residence postal code"),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }
    val ResidentStreet: AttributeDetails by lazy {
        AttributeDetails(
            name = "resident_street",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Residence street"),
            operationSetter = OperationsRequestorType::setPlaceOfResidence
        )
    }

    val Nationality: AttributeDetails by lazy {
        AttributeDetails(
            name = "nationality",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Nationality"),
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
            name = "family_name_birth",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
            operationSetter = OperationsRequestorType::setBirthName
        )
    }

    val pidAttributes = listOf(
        FamilyName,
        GivenName,
        BirthDate,
        AgeEqualOrOver,
        AgeInYears,
        AgeOver18,
        IssuanceDate,
        BirthDateYear,
        Gender,
        Nationality,
        FamiltyNameBirth,
        BirthCity,
        BirthPlace,
        BirthState,
        BirthCountry,
        ResidentCity,
        ResidentState,
        ResidentStreet,
        ResidentAddress,
        ResidentPostalCode,
        ResidentCountry,
        ExpiryDate,
        IssuingCountry,
        IssuingAuthority,
        SourceDocumentType
    )
}

fun pidSdJwtVcV1(vararg signingAlgorithm: JWSAlgorithm): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSdJwtVcScope.value),
        type = SdJwtVcType(pidDocType(1)),
        display = pidDisplay,
        claims = Attributes.pidAttributes,
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = signingAlgorithm.toSet().toNonEmptySetOrNull()!!,
        scope = PidSdJwtVcScope,
        proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
    )

typealias TimeDependant<F> = (ZonedDateTime) -> F

private val log = LoggerFactory.getLogger(IssueSdJwtVcPid::class.java)

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSdJwtVcPid(
    credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val getPidData: GetPidData,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    calculateExpiresAt: TimeDependant<Instant>,
    calculateNotUseBefore: TimeDependant<Instant>?,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredential: StoreIssuedCredential,
) : IssueSpecificCredential<JsonElement> {

    private val validateProof = ValidateProof(credentialIssuerId)

    override val supportedCredential: SdJwtVcCredentialConfiguration =
        pidSdJwtVcV1(issuerSigningKey.signingAlgorithm, issuerSigningKey.authenticatedChannelAlgorithm)
    override val publicKey: JWK
        get() = issuerSigningKey.key.toPublicJWK()

    private val encodePidInSdJwt = EncodePidInSdJwtVc(
        credentialIssuerId,
        clock,
        hashAlgorithm,
        issuerSigningKey,
        calculateExpiresAt,
        calculateNotUseBefore,
        supportedCredential.type,
    )

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val sdJwt = encodePidInSdJwt(pid, pidMetaData, holderPubKey.await(), request.verifierKA)

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null
        storeIssuedCredential(
            IssuedCredential(
                format = SD_JWT_VC_FORMAT,
                type = supportedCredential.type.value,
                holderPublicKey = holderPubKey.await().toPublicJWK(),
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(JsonPrimitive(sdJwt), notificationId)
            .also {
                log.info("Successfully issued PID")
                log.debug("Issued PID data {}", it)
            }
    }

    context(Raise<InvalidProof>)
    private suspend fun holderPubKey(
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): JWK {
        val key = validateProof(request.unvalidatedProof, expectedCNonce, supportedCredential)
        return extractJwkFromCredentialKey(key)
            .getOrElse {
                raise(InvalidProof("Unable to extract JWK from CredentialKey", it))
            }
    }
}
