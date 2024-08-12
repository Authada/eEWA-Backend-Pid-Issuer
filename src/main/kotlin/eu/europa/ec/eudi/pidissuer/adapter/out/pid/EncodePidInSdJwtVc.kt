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
import eu.europa.ec.eudi.sdjwt.sd
import eu.europa.ec.eudi.sdjwt.sdJwt
import eu.europa.ec.eudi.sdjwt.serialize
import eu.europa.ec.eudi.sdjwt.value
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime

private val log = LoggerFactory.getLogger(EncodePidInSdJwtVc::class.java)

class EncodePidInSdJwtVc(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val hashAlgorithm: HashAlgorithm,
    private val issuerSigningKey: IssuerSigningKey,
    private val calculateExpiresAt: TimeDependant<Instant>,
    private val calculateNotUseBefore: TimeDependant<Instant>?,
    private val vct: SdJwtVcType,
) {


    context(Raise<IssueCredentialError>)
    operator fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: JWK,
        verifierKA: VerifierKA?
    ): String {
        val at = clock.instant().atZone(clock.zone)
        val sdJwtSpec = selectivelyDisclosed(
            pid = pid,
            pidMetaData = pidMetaData,
            vct = vct,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderKey,
            iat = at,
            exp = calculateExpiresAt(at),
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
    pidMetaData: PidMetaData,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
    holderPubKey: JWK,
    iat: ZonedDateTime,
    exp: Instant,
    nbf: Instant?,
): SdObject {
    require(exp.epochSecond > iat.toInstant().epochSecond) { "exp should be after iat" }
    nbf?.let {
        require(nbf.epochSecond > iat.toInstant().epochSecond) { "nbe should be after iat" }
    }

    return sdJwt {
        //
        // Always disclosed claims
        //
        iss(credentialIssuerId.externalForm)
        iat(iat.toInstant().epochSecond)
        nbf?.let { nbf(it.epochSecond) }
        exp(exp.epochSecond)
        cnf(holderPubKey)
        plain("vct", vct.value)
        plain("vct#integrity", "sha256-61b265b61f8b3da65572737dca256474b3d491e971aa54919f98fa7c35f11dd6")

        pidMetaData.issuanceDate?.let {
            sd(Attributes.IssuanceDate.name, pidMetaData.issuanceDate.toString())
        }
        pidMetaData.expiryDate?.let {
            sd(Attributes.ExpiryDate.name, pidMetaData.expiryDate.toString())
        }
        pidMetaData.issuingCountry?.let {
            sd(Attributes.IssuingCountry.name, pidMetaData.issuingCountry.value)
        }
        pidMetaData.issuingAuthority?.let {
            sd(
                Attributes.IssuingAuthority.name,
                (pidMetaData.issuingAuthority as MemberState).code.value
            )
        }
        pidMetaData.sourceType?.let { sd(Attributes.SourceDocumentType.name, it) }
        pid.givenName?.let { sd(Attributes.GivenName.name, pid.givenName.value) }
        pid.familyName?.let { sd(Attributes.FamilyName.name, pid.familyName.value) }
        pid.birthDate?.let { sd(Attributes.BirthDate.name, pid.birthDate.toString()) }
        pid.ageOver18?.let { sd(Attributes.AgeOver18.name, it) }

        pid.gender?.let { sd(Attributes.Gender.name, it.value.toInt()) }
        pid.nationality?.let { sd(Attributes.Nationality.name, it.value) }
        pid.ageInYears?.let { sd(Attributes.AgeInYears.name, it.toString()) }
        pid.ageBirthYear?.let { sd(Attributes.BirthDateYear.name, it.value.toString()) }
        pid.familyNameBirth?.let { sd(Attributes.FamiltyNameBirth.name, it.value) }
        pid.birthCountry?.let { sd(Attributes.BirthCountry.name, it.value) }
        pid.birthCity?.let { sd(Attributes.BirthCity.name, it.value) }
        pid.birthPlace?.let { sd(Attributes.BirthPlace.name, it) }
        pid.birthState?.let { sd(Attributes.BirthState.name, it.value) }

        pid.residentCity?.let { sd(Attributes.ResidentCity.name, it.value) }
        pid.residentCountry?.let { sd(Attributes.ResidentCountry.name, it.value) }
        pid.residentStreet?.let { sd(Attributes.ResidentStreet.name, it.value) }
        pid.residentPostalCode?.let { sd(Attributes.ResidentPostalCode.name, it.value) }
        pid.residentState?.let { sd(Attributes.ResidentState.name, it.value) }
        pid.residentAddress?.let { sd(Attributes.ResidentAddress.name, it) }
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
