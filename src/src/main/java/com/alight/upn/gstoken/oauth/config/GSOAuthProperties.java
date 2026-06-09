package com.alight.upn.gstoken.oauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Configuration
@RefreshScope
@Component
public class GSOAuthProperties
{

	@Value("${nextcapital.jwt-signing-key-alias}")
	private String jwtSigningKeyAlias;

	@Value("${nextcapital.keystore-location}")
	private String keystoreLocation;

	@Value("${nextcapital.authUrl}")
	private String authUrl;

	@Value("${nextcapital.proxyEndpoint}")
	private String proxyEndpoint;

	@Value("${spring.config.activate.on-profile}")
	private String lifecycle;

	public String getJwtSigningKeyAlias() {
		return jwtSigningKeyAlias;
	}

	public String getKeystoreLocation() {
		return keystoreLocation;
	}

	public String getAuthUrl() {
		return authUrl;
	}

	public String getProxyEndpoint() {
		return proxyEndpoint;
	}

	public String getLifecycle() {
		return lifecycle;
	}

	public void setJwtSigningKeyAlias(String jwtSigningKeyAlias) {
		this.jwtSigningKeyAlias = jwtSigningKeyAlias;
	}

	public void setKeystoreLocation(String keystoreLocation) {
		this.keystoreLocation = keystoreLocation;
	}

	public void setAuthUrl(String authUrl) {
		this.authUrl = authUrl;
	}

	public void setProxyEndpoint(String proxyEndpoint) {
		this.proxyEndpoint = proxyEndpoint;
	}

	public void setLifecycle(String lifecycle) {
		this.lifecycle = lifecycle;
	}

}
