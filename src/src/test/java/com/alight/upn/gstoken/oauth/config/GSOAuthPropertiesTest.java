package com.alight.upn.gstoken.oauth.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
public class GSOAuthPropertiesTest {

    @InjectMocks
    private GSOAuthProperties properties;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testJwtSigningKeyAlias() {
        properties.setJwtSigningKeyAlias("alias123");
        Assertions.assertEquals("alias123", properties.getJwtSigningKeyAlias());
        Assertions.assertEquals("alias123", properties.getJwtSigningKeyAlias());
    }

    @Test
    public void testKeystoreLocation() {
        properties.setKeystoreLocation("/path/to/keystore");
        Assertions.assertEquals("/path/to/keystore", properties.getKeystoreLocation());
    }

    @Test
    public void testAuthUrl() {
        properties.setAuthUrl("https://auth.example.com");
        Assertions.assertEquals("https://auth.example.com", properties.getAuthUrl());
    }

    @Test
    public void testProxyEndpoint() {
        properties.setProxyEndpoint("https://proxy.example.com");
        Assertions.assertEquals("https://proxy.example.com", properties.getProxyEndpoint());

        properties.setAuthUrl("https://gs.example.com");
        Assertions.assertEquals("https://gs.example.com", properties.getAuthUrl());
    }

    @Test
    public void testLifecycle() {
        properties.setLifecycle("dev");
        Assertions.assertEquals("dev", properties.getLifecycle());
    }
}
