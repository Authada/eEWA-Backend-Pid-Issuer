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
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.Encode
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.IssuingAuthority.MemberState
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.sdjwt.Disclosure
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdObject
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.exp
import eu.europa.ec.eudi.sdjwt.iat
import eu.europa.ec.eudi.sdjwt.iss
import eu.europa.ec.eudi.sdjwt.nbf
import eu.europa.ec.eudi.sdjwt.plain
import eu.europa.ec.eudi.sdjwt.recursive
import eu.europa.ec.eudi.sdjwt.sd
import eu.europa.ec.eudi.sdjwt.sdJwt
import eu.europa.ec.eudi.sdjwt.serialize
import eu.europa.ec.eudi.sdjwt.value
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.LocalTime
import java.time.ZoneOffset

private val log = LoggerFactory.getLogger(EncodePidInSdJwtVc::class.java)

class EncodePidInSdJwtVc(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
    private val docType: SdJwtVcType = pidDocType(1)
) : Encode<Pid> {
    context(Raise<IssueCredentialError>)
    override suspend operator fun invoke(
        data: Pid,
        holderKey: JWK,
        verifierKA: VerifierKA?
    ): String {
        val at = clock.instant().atZone(clock.zone)
        val sdJwtSpec = selectivelyDisclosed(
            pid = data,
            vct = docType,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderKey,
            nbf = calculateNotUseBefore?.let { calculate -> calculate(at) },
        )

        val sdJwtIssuer = verifierKA?.let {
            AuthenticatedChannelIssuer(hashAlgorithm, issuerSigningKey, it)
        } ?: SignedIssuer(hashAlgorithm, issuerSigningKey, null)
        val issuedSdJwt: SdJwt.Issuance<SignedJWT> = sdJwtIssuer.issue(sdJwtSpec).getOrElse {
            raise(Unexpected("Error while creating SD-JWT", it))
        }
        if (log.isInfoEnabled) {
            log.info(with(Printer) { issuedSdJwt.prettyPrint() })
        }

        return issuedSdJwt.serialize()
    }
}

fun selectivelyDisclosed(
    pid: Pid,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
    holderPubKey: JWK,
    nbf: Instant?,
): SdObject {

    return sdJwt {
        //
        // Always disclosed claims
        //
        iss(credentialIssuerId)
        nbf?.let { nbf(it.epochSecond) }
        cnf(holderPubKey)
        plain("vct", vct)
        plain("vct#integrity", "sha256-06af3f5d575943508300a4361113ef3580a6c771d36eaa1f2f2f1fe8764acf33")

        pid.metaData.issuanceDate?.let {
            iat(it.toEpochSecond(LocalTime.ofSecondOfDay(0), ZoneOffset.UTC))
        }
        pid.metaData.expiryDate?.let {
            exp(it.toEpochSecond(LocalTime.ofSecondOfDay(0), ZoneOffset.UTC))
        }
        pid.metaData.issuingCountry?.let {
            sd(Attributes.IssuingCountry.name, it.value)
        }
        pid.metaData.issuingAuthority?.let {
            sd(
                Attributes.IssuingAuthority.name,
                (it as MemberState).code.value
            )
        }
        pid.metaData.sourceType?.let { sd(Attributes.SourceDocumentType.name, it) }
        pid.givenName?.let { sd(Attributes.GivenName.name, pid.givenName.value) }
        pid.familyName?.let { sd(Attributes.FamilyName.name, pid.familyName.value) }
        pid.birthDate?.let { sd(Attributes.BirthDate.name, pid.birthDate.toString()) }

        pid.nationality?.let {
            sd(Attributes.Nationality.name, buildJsonArray { add(it.value) })
        }
        pid.ageInYears?.let { sd(Attributes.AgeInYears.name, it.toString()) }
        pid.ageOver18?.let {
            recursive(Attributes.AgeEqualOrOver.name) {
                sd("18", it)
            }
        }
        pid.ageBirthYear?.let { sd(Attributes.BirthDateYear.name, it.value.toString()) }
        pid.familyNameBirth?.let { sd(Attributes.FamiltyNameBirth.name, it.value) }
        pid.alsoKnownAs?.let { sd(Attributes.AlsoKnownAs.name, it) }
        if (pid.birthCity != null || pid.birthPlace != null || pid.birthCountry != null || pid.birthState != null) {
            recursive(Attributes.BirthPlace.name) {
                (pid.birthPlace ?: pid.birthCity?.value)?.let { sd("locality", it) }
                pid.birthState?.let { sd("region", it.value) }
                pid.birthCountry?.let { sd("country", it.value) }
            }
        }

        if (pid.residentCity != null ||
            pid.residentState != null ||
            pid.residentStreet != null ||
            pid.residentAddress != null ||
            pid.residentCountry != null ||
            pid.residentPostalCode != null
        ) {
            recursive(Attributes.Address.name) {
                pid.residentAddress?.let { sd("formatted", it) }
                pid.residentCountry?.let { sd("country", it.value) }
                pid.residentState?.let { sd("region", it.value) }
                pid.residentCity?.let { sd("locality", it.value) }
                pid.residentPostalCode?.let { sd("postal_code", it.value) }
                pid.residentStreet?.let { sd("street_address", it.value) }
            }
        }
    }
}

object Printer {
    val json = Json { prettyPrint = true }
    private fun JsonElement.pretty(): String = json.encodeToString(this)
    fun SdJwt.Issuance<SignedJWT>.prettyPrint(): String {
        var str = "\nSD-JWT with ${disclosures.size} disclosures\n"
        disclosures.forEach { d ->
            val kind = when (d) {
                is Disclosure.ArrayElement -> "\t - ArrayEntry ${d.claim().value().pretty()}"
                is Disclosure.ObjectProperty -> "\t - ObjectProperty ${d.claim().first} = ${d.claim().second}"
            }
            str += kind + "\n"
        }
        str += "SD-JWT payload\n"
        str += json.parseToJsonElement(jwt.jwtClaimsSet.toString()).run {
            json.encodeToString(this)
        }
        str += "\nSD-JWT signature\n"
        str += jwt.signature
        str += "\nSD-JWT headers\n"
        str += jwt.header.toJSONObject()
        return str
    }
}
