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
package eu.europa.ec.eudi.pidissuer.adapter.input.web.security

import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAccessTokenMetadataByToken
import org.slf4j.LoggerFactory
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import reactor.core.publisher.Mono
import java.time.Clock
import java.time.Instant


class DPoPLocalIntrospector(
    private val getPrincipal: GetAccessTokenMetadataByToken,
    private val clock: Clock
) : ReactiveOpaqueTokenIntrospector {
    override fun introspect(token: String?): Mono<OAuth2AuthenticatedPrincipal> {
        log.info("Getting Principal for token {}", token)
        return Mono.fromCallable {
            getPrincipal(token!!).run {
                val principalAttributes = mapOf(
                    OAuth2TokenIntrospectionClaimNames.CLIENT_ID to this.clientId,
                    OAuth2TokenIntrospectionClaimNames.NBF to this.notBefore,
                    OAuth2TokenIntrospectionClaimNames.ISS to this.clientId,
                    OAuth2TokenIntrospectionClaimNames.SUB to this.clientId,
                    OAuth2TokenIntrospectionClaimNames.USERNAME to this.clientId,
                    OAuth2TokenIntrospectionClaimNames.EXP to this.expiration,
                    "cnf" to mapOf("jkt" to this.jwkThumbprint.toString()),
                    OAuth2TokenIntrospectionClaimNames.ACTIVE to checkActive(this.expiration, this.notBefore)
                )
                val principal = DefaultOAuth2AuthenticatedPrincipal(
                    principalAttributes,
                    this.scope.map { SimpleGrantedAuthority("SCOPE_$it") }
                ) //TODO reicht active oder sollte hier ne exception fliegen?
                //TODO realm?

                log.info("Retrieved Principal attributes {}", principalAttributes)
                log.info("Returning Principal {}", principal.authorities.map { it.authority })
                principal
            }
        }
    }

    private fun checkActive(expiration: Instant, notBefore: Instant): Boolean =
        clock.instant().let { now ->
            now.isBefore(expiration) && now.isAfter(notBefore)
        }

    companion object {
        private val log = LoggerFactory.getLogger(DPoPLocalIntrospector::class.java)
    }
}
