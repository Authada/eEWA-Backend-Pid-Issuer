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
package eu.europa.ec.eudi.pidissuer

import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryWalletAttestationNonceRepository
import eu.europa.ec.eudi.pidissuer.domain.ValidateWalletAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.DeleteExpiredCNonce
import kotlinx.coroutines.runBlocking
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler
import java.time.Clock
import java.time.Duration

class CleanupScheduler(
    private val deleteExpiredCNonce: DeleteExpiredCNonce,
    private val inMemoryWalletAttestationNonceRepository: InMemoryWalletAttestationNonceRepository,
    private val validateWalletAttestation: ValidateWalletAttestation,
    private val clock: Clock
) {

    private val scheduler = ThreadPoolTaskScheduler().also {
        it.poolSize = 1
        it.initialize()
    }

    init {
        scheduler.scheduleWithFixedDelay(
            {
                runBlocking {
                    deleteExpiredCNonce.invoke(clock.instant())
                    inMemoryWalletAttestationNonceRepository.deleteExpiredNonces()
                    validateWalletAttestation.clearExpired()
                }
            },
            Duration.ofMinutes(1)
        )
    }
}
