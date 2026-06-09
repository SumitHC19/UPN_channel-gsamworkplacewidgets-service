package com.alight.upn.gstoken.oauth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import com.alight.cloud.feign.config.UpointFeignProxyConfiguration;


@FeignClient(name = "personauthorization", configuration = UpointFeignProxyConfiguration.class)
public interface PersonAuthorizationFeignClient {
  
  @GetMapping("/authenticateRacfId")
  ResponseEntity<String> isRACFAuthorized(
      @RequestHeader String alightColleagueSessionToken,
      @RequestHeader String racfProfile);
  
}
