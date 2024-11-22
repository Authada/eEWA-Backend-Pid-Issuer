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

import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.Encode
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Printer
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.SignedIssuer
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdObject
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.exp
import eu.europa.ec.eudi.sdjwt.iat
import eu.europa.ec.eudi.sdjwt.iss
import eu.europa.ec.eudi.sdjwt.plain
import eu.europa.ec.eudi.sdjwt.sd
import eu.europa.ec.eudi.sdjwt.sdJwt
import eu.europa.ec.eudi.sdjwt.serialize
import org.slf4j.LoggerFactory
import java.time.LocalTime
import java.time.ZoneOffset

private val log = LoggerFactory.getLogger(EncodeEmailInSdJwtVc::class.java)

class EncodeEmailInSdJwtVc(
    private val hashAlgorithm: HashAlgorithm,
    private val credentialIssuerId: CredentialIssuerId,
    private val issuerSigningKey: IssuerSigningKey,
    private val docType: SdJwtVcType = emailDocType(1)
) : Encode<EmailData> {

    context(Raise<IssueCredentialError>)
    override suspend operator fun invoke(
        data: EmailData,
        holderKey: JWK,
        verifierKA: VerifierKA?
    ): String {
        val sdJwtSpec = selectivelyDisclosed(
            emailData = data,
            vct = docType,
            credentialIssuerId = credentialIssuerId,
            holderPubKey = holderKey,
        )

        val sdJwtIssuer = SignedIssuer(hashAlgorithm, issuerSigningKey, null)
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
    emailData: EmailData,
    credentialIssuerId: CredentialIssuerId,
    vct: SdJwtVcType,
    holderPubKey: JWK,
): SdObject = sdJwt {
    //
    // Always disclosed claims
    //
    iss(credentialIssuerId)
    cnf(holderPubKey)
    plain("vct", vct)
    plain("vct#integrity", "sha256-61b265b61f8b3da65572737dca256474b3d491e971aa54919f98fa7c35f11dd6")

    emailData.issuanceDate.let {
        iat(it.toEpochSecond(LocalTime.ofSecondOfDay(0), ZoneOffset.UTC))
    }
    emailData.expiryDate.let {
        exp(it.toEpochSecond(LocalTime.ofSecondOfDay(0), ZoneOffset.UTC))
    }
    emailData.email.let {
        sd(Attributes.EmailAttribute.name, emailData.email.value)
    }
}
