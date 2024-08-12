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
package eu.europa.ec.eudi.pidissuer.eid

import de.bund.bsi.eid.EID
import de.bund.bsi.eid.GeneralDateType
import de.bund.bsi.eid.GeneralPlaceType
import de.bund.bsi.eid.GetResultRequestType
import de.bund.bsi.eid.GetResultResponseType
import de.bund.bsi.eid.GetServerInfoResponseType
import de.bund.bsi.eid.NullType
import de.bund.bsi.eid.PersonalDataType
import de.bund.bsi.eid.PlaceType
import de.bund.bsi.eid.PreSharedKeyType
import de.bund.bsi.eid.SessionType
import de.bund.bsi.eid.UseIDRequestType
import de.bund.bsi.eid.UseIDResponseType
import oasis.names.tc.dss._1_0.core.schema.Result
import java.time.ZoneId
import java.util.TimeZone
import java.util.UUID
import javax.xml.datatype.DatatypeFactory

class EidMock : EID {
    override fun useID(parameters: UseIDRequestType?): UseIDResponseType {
        return UseIDResponseType().apply {
            this.psk = PreSharedKeyType().apply {
                id = UUID.randomUUID().toString()
                key = byteArrayOf(0)
            }
            this.eCardServerAddress = "https://mock"
            this.session = SessionType().apply {
                this.id = byteArrayOf(1)
            }
            this.result = Result().apply {
                this.resultMajor = "ok"
            }
        }
    }

    override fun getResult(parameters: GetResultRequestType?): GetResultResponseType = GetResultResponseType().apply {
        this.result = Result().apply {
            this.resultMajor = "ok"
        }
        this.personalData = PersonalDataType().apply {
            this.familyNames = "Deutscher"
            this.givenNames = "Personalausweis"
            this.dateOfBirth = GeneralDateType().apply {
                this.dateValue = DatatypeFactory.newInstance().newXMLGregorianCalendarDate(2200, 1, 1, TimeZone.getTimeZone(
                    ZoneId.of("UTC")).rawOffset)
                this.dateString = "22000101"
            }
            this.placeOfResidence = GeneralPlaceType()
            this.placeOfResidence.noPlaceInfo = "Test"
            this.placeOfResidence.freetextPlace = "Test"
            this.placeOfResidence.structuredPlace = PlaceType().apply {
                this.city = "Test"
                this.state = "Test"
                this.country = "D"
                this.street = "Test 1"
                this.zipCode = "12345"
            }
            this.placeOfBirth = GeneralPlaceType()
            this.placeOfBirth.noPlaceInfo = "Test"
            this.placeOfBirth.freetextPlace = "Test"
            this.placeOfBirth.structuredPlace = PlaceType().apply {
                this.city = "Test"
                this.state = "Test"
                this.country = "D"
                this.street = "Test 1"
                this.zipCode = "12345"
            }
            this.academicTitle = "Test"
            this.artisticName = "Test"
            this.nationality = "D"
            this.documentType = "ID"
            this.residencePermitI = "Test"
            this.birthName = "Test"
            this.issuingState = "D"
            this.dateOfExpiry = DatatypeFactory.newInstance().newXMLGregorianCalendarDate(2200, 1, 1, TimeZone.getTimeZone(
                ZoneId.of("UTC")).rawOffset)
        }
    }

    override fun getServerInfo(parameters: NullType?): GetServerInfoResponseType {
        TODO("Not yet implemented")
    }
}
