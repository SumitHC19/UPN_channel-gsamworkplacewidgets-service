package com.alight.upn.gstoken.oauth.helper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.alight.portal.core.udp.v2.dto.person.PersonsV2;
import com.alight.upn.gstoken.oauth.feign.PersonsV2FeignClient;
import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;


@Component
public class PersonV2Helper {

	@Autowired
	private PersonsV2FeignClient personV2Response;

	public String getGlobalPersonIdentifier() {
		try {
			ResponseEntity<PersonsV2> personsV2 = personV2Response.getPersonsV2Response();
			PersonsV2 personContactResponse = personsV2 != null ? personsV2.getBody() : null;

			return (personContactResponse != null ? personContactResponse.getGlobalPersonIdentifier() : null);

		} catch (Exception e) {
			ErrorLogEventHelper.logErrorEvent("GetPersonV2",
					"Error while fetching Global PersonIdentifier", "getGlobalPersonIdentifier()",
					e, ErrorLogEvent.ERROR_SEVERITY);
		}
		return null;
	}

}
