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

import eu.europa.ec.eudi.pidissuer.domain.CredentialDisplay
import eu.europa.ec.eudi.pidissuer.domain.DisplayName
import eu.europa.ec.eudi.pidissuer.domain.ImageUri
import java.net.URI
import java.util.Locale.ENGLISH

internal const val PID_DOCTYPE = "eu.europa.ec.eudi.pid"
internal const val PID_DOCTYPE_SDJWTVC = "https://example.bmi.bund.de/credential/pid/1.0"
internal const val PID_DOCTYPE_SDJWTVC_NEW = "https://metadata-8c062a.usercontent.opencode.de/pid.json"

internal fun pidDocType(v: Int?): String =
    if (v == null) PID_DOCTYPE
    else "$PID_DOCTYPE.$v"

val pidDisplay = listOf(
    CredentialDisplay(
        name = DisplayName("ID card", ENGLISH),
        logo = ImageUri(
            URI.create("https://authada.de/customerlogos/authada_light.png"),
            alternativeText = "AUTHADA logo"
        ),
        description = "eEWA PID Prototype",
        backgroundColor = "#aaaaaa",
        backgroundImage = ImageUri(
            URI.create("https://authada.de/customerlogos/authada_dark.png"),
            alternativeText = "AUTHADA dark logo"
        ),
        textColor = "#6e23d2"
    ),
)
