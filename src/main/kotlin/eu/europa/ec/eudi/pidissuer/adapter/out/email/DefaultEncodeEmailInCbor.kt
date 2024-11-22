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
import eu.europa.ec.eudi.pidissuer.adapter.out.Encode
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.MsoMdocSigner
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import id.walt.mdoc.dataelement.toDataElement
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import kotlin.time.Duration

class DefaultEncodeEmailInCbor(
    clock: Clock,
    issuerSigningKey: IssuerSigningKey,
    validityDuration: Duration,
) : Encode<EmailData> {

    private val signer = MsoMdocSigner<EmailData>(
        clock = clock,
        issuerSigningKey = issuerSigningKey,
        validityDuration = validityDuration,
        docType = EMAIL_DOCTYPE,
    ) { emailData ->

        addItemToSign(EMAIL_DOCTYPE, MdocAttributes.EmailAttribute.name, emailData.email.value.toDataElement())
        addItemToSign(
            EMAIL_DOCTYPE,
            MdocAttributes.IssuanceDate.name,
            emailData.issuanceDate.toKotlinLocalDate().toDataElement()
        )
        addItemToSign(
            EMAIL_DOCTYPE,
            MdocAttributes.ExpiryDate.name,
            emailData.expiryDate.toKotlinLocalDate().toDataElement()
        )
    }


    context(Raise<IssueCredentialError>) override suspend fun invoke(
        data: EmailData,
        holderKey: JWK,
        verifierKA: VerifierKA?
    ): String =
        try {
            signer.sign(data, holderKey.toECKey())
        } catch (t: Throwable) {
            raise(Unexpected("Failed to encode mDL", t))
        }
}
