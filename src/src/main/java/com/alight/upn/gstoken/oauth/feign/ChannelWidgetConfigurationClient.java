package com.alight.upn.gstoken.oauth.feign;

import java.util.List;
import java.util.Map;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.alight.cloud.feign.config.UpointFeignProxyConfiguration;
import com.aonhewitt.beans.GenericRequestBean;

/**
 * 
 * This feign client is used to call channel-widgetconfiguration-service API to fetch config data for given card.
 */

@Component
@FeignClient(name = "channel-widgetconfigurations", configuration=UpointFeignProxyConfiguration.class)
public interface ChannelWidgetConfigurationClient {
	
	@PostMapping( value = "/channel/configurationList/get", consumes = "application/json")
	List<Map<Object, Object>> getListOfAsset(@RequestBody GenericRequestBean genericBean);

}
