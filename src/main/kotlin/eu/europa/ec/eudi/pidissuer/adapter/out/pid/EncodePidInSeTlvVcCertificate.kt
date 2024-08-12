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
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.pidissuer.domain.tlv.PIDTLVPayload
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(EncodePidInSdJwtVc::class.java)

class EncodePidInSeTlvVcCertificate(
    private val issuer: AuthenticatedChannelCertificateIssuer
) {

    context(Raise<IssueCredentialError>)
    operator fun invoke(
        pid: Pid,
        pidMetaData: PidMetaData,
        holderKey: JWK,
    ): Base64URL {
        val seTlv = PIDTLVPayload(pid, pidMetaData)

        val issue = issuer(holderKey)
        val issuedSeTlvVc: Base64URL = issue(seTlv).getOrElse {
            raise(Unexpected("Error while creating CWT", it))
        }
        if (log.isInfoEnabled) {
            log.info(issuedSeTlvVc.toString())
        }

        return issuedSeTlvVc
    }
}
