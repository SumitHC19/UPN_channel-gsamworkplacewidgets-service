package com.alight.upn.gstoken.oauth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import com.alight.cloud.feign.config.UpointFeignProxyConfiguration;
import com.alight.portal.core.udp.v2.dto.person.PersonsV2;


@FeignClient(value = "persons-v2", configuration = UpointFeignProxyConfiguration.class)
//@FeignClient(value = "persons-v2", url = "https://api-dv.ap.alight.com/api/v2/persons")
public interface PersonsV2FeignClient {
	
	@GetMapping(value = "/", consumes = "application/json")
	public ResponseEntity<PersonsV2> getPersonsV2Response();
	
}
