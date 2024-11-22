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
package eu.europa.ec.eudi.pidissuer.adapter.out

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialIdentifier
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse.Issued
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock


private val log = LoggerFactory.getLogger(IssueGeneric::class.java)


fun interface GetData<T> {
    suspend operator fun invoke(username: Username): T?

    context (Raise<IssueCredentialError.Unexpected>)
    suspend operator fun invoke(authorizationContext: AuthorizationContext): T {
        val data = invoke(authorizationContext.username!!)
        return ensureNotNull(data) { IssueCredentialError.Unexpected("Cannot obtain data") }
    }
}

/**
 * Service for issuing verified email SD JWT credential
 */
class IssueGeneric<A>(
    private val clock: Clock,
    private val getData: GetData<A>,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredential: StoreIssuedCredential,
    override val supportedCredential: CredentialConfiguration<A>
) : IssueSpecificCredential<JsonElement> {

    private val validateProof = ValidateProof(supportedCredential.issuerId)

    override val publicKey: JWK?
        get() = supportedCredential.issuerSigningKey?.key?.toPublicJWK()


    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = holderPubKey(request, expectedCNonce)
        val data = getData(authorizationContext)
        val sdJwt = supportedCredential.encode(data, holderPubKey, request.verifierKA)

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null
        storeIssuedCredential(
            IssuedCredential(
                format = supportedCredential.format,
                type = supportedCredential.docType,
                holderPublicKey = holderPubKey.toPublicJWK(),
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        Issued(JsonPrimitive(sdJwt), notificationId)
            .also {
                log.info("Successfully issued")
                log.debug("Issued data {}", it)
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
