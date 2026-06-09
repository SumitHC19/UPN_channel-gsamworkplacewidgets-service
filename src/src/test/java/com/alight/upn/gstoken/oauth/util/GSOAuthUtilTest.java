package com.alight.upn.gstoken.oauth.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.alight.asg.model.token.v1_0.ColleagueSessionToken;
import com.alight.asg.model.token.v1_0.IdMapping;
import com.alight.asg.model.token.v1_0.PersonSessionToken;
import com.alight.asg.service.ServiceDelegator;
import com.alight.cloud.data.store.util.DockerSecretsUtil;
import com.alight.portal.core.udp.v2.dto.person.PersonsV2;
import com.alight.upn.gstoken.oauth.config.GSOAuthProperties;
import com.alight.upn.gstoken.oauth.constant.GSAMConstants;
import com.alight.upn.gstoken.oauth.feign.ChannelWidgetConfigurationClient;
import com.alight.upn.gstoken.oauth.feign.PersonAuthorizationFeignClient;
import com.alight.upn.gstoken.oauth.feign.PersonsV2FeignClient;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.http.HttpServletRequest;

class GSOAuthUtilTest {

    @Mock private GSOAuthProperties oauthProps;
    @Mock private ChannelWidgetConfigurationClient widgetClient;
    @Mock private PersonAuthorizationFeignClient authClient;
    @Mock private PersonsV2FeignClient personsV2FeignClient;
    @Mock private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetSecret_WhenSecretExists_ShouldReturnTrimmedValue() throws Exception {
        Map<String, String> secrets = new HashMap<>();
        secrets.put("my-secret", "  secretValue  ");
        try (MockedStatic<DockerSecretsUtil> mocked = mockStatic(DockerSecretsUtil.class)) {
            mocked.when(DockerSecretsUtil::load).thenReturn(secrets);
            String result = GSOAuthUtil.getSecret("my-secret", "dev");
            assertEquals("secretValue", result);
        }
    }

    @Test
    void testGetSecret_WhenSecretMissing_ShouldThrowException() {
        try (MockedStatic<DockerSecretsUtil> mocked = mockStatic(DockerSecretsUtil.class)) {
            mocked.when(DockerSecretsUtil::load).thenReturn(Collections.emptyMap());
            Exception ex = assertThrows(Exception.class, () -> GSOAuthUtil.getSecret("missing", "dev"));
            assertTrue(ex.getMessage().contains("not found"));
        }
    }

    @Test
    void testGetSigningKey_WhenKeyRetrievedSuccessfully() throws Exception {
        PrivateKey mockKey = mock(RSAPrivateKey.class);
        AlightKeyStore mockStore = mock(AlightKeyStore.class);

        when(oauthProps.getJwtSigningKeyAlias()).thenReturn("alias");
        when(oauthProps.getKeystoreLocation()).thenReturn("location");
        when(mockStore.getPrivateKey("alias", oauthProps)).thenReturn(mockKey);

        try (MockedStatic<AlightKeyStore> mocked = mockStatic(AlightKeyStore.class)) {
            mocked.when(AlightKeyStore::getInstance).thenReturn(mockStore);
            PrivateKey result = GSOAuthUtil.getSigningKey(oauthProps);
            assertEquals(mockKey, result);
        }
    }

    @Test
    void testGetSigningKey_WhenKeyFails_ShouldThrowException() throws Exception {
        AlightKeyStore mockStore = mock(AlightKeyStore.class);
        when(oauthProps.getJwtSigningKeyAlias()).thenReturn("alias");
        when(oauthProps.getKeystoreLocation()).thenReturn("location");
        when(mockStore.getPrivateKey(any(), any())).thenThrow(new RuntimeException("Key error"));

        try (MockedStatic<AlightKeyStore> mocked = mockStatic(AlightKeyStore.class)) {
            mocked.when(AlightKeyStore::getInstance).thenReturn(mockStore);
            Exception ex = assertThrows(Exception.class, () -> GSOAuthUtil.getSigningKey(oauthProps));
            assertTrue(ex.getMessage().contains("Unable to read signing key"));
        }
    }

    @Test
    void testGetSignedJWT_ShouldReturnSignedToken() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        IdMapping idMapping = new IdMapping();
        idMapping.setDomain("dc");
        idMapping.setClientId("client123");
        idMapping.setNormalizedClientId("normClient");
        idMapping.setPlatformInternalId("platformId");
        idMapping.setSystemInstanceId("sysId");
        idMapping.setSourceTestCfg("sourceCfg");

        PersonSessionToken pst = new PersonSessionToken();
        pst.setIdMapping(List.of(idMapping));
        pst.setTestCfg("testCfg");

        try (MockedConstruction<ServiceDelegator> mocked = Mockito.mockConstruction(ServiceDelegator.class,
                (mock, context) -> when(mock.getPersonSessionToken()).thenReturn(pst))) {

            try (MockedStatic<RequestContextHolder> contextHolder = mockStatic(RequestContextHolder.class)) {
                ServletRequestAttributes attrs = mock(ServletRequestAttributes.class);
                contextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(attrs);
                when(attrs.getRequest()).thenReturn(request);
                when(request.getHeader(GSAMConstants.COLLEAGUE_SESSION_TOKEN)).thenReturn("mockToken");

                ColleagueSessionToken mockCSToken = mock(ColleagueSessionToken.class);
                when(mockCSToken.getColleagueSessionMapEntry(GSAMConstants.CRED_RACF_ID)).thenReturn("racf123");

                try (MockedStatic<ColleagueSessionToken> tokenStatic = mockStatic(ColleagueSessionToken.class)) {
                    tokenStatic.when(() -> ColleagueSessionToken.parse("mockToken")).thenReturn(mockCSToken);

                    Map<Object, Object> uceMap = new HashMap<>();
                    uceMap.put(GSAMConstants.IRA_RACF_AUTH_PROFILE_TXT, "racfProfile");
                    Map<Object, Object> configMap = new HashMap<>();
                    configMap.put(GSAMConstants.TEXT_UCE, uceMap);
                    when(widgetClient.getListOfAsset(any())).thenReturn(List.of(configMap));

                    when(authClient.isRACFAuthorized(anyString(), anyString()))
                            .thenReturn(new ResponseEntity<>("OK", HttpStatus.OK));

                    PersonsV2 persons = new PersonsV2();
                    persons.setGlobalPersonIdentifier("globalId");
                    when(personsV2FeignClient.getPersonsV2Response())
                            .thenReturn(new ResponseEntity<>(persons, HttpStatus.OK));

                    try (MockedStatic<GSOAuthUtil> utilMock = mockStatic(GSOAuthUtil.class, CALLS_REAL_METHODS)) {
                        utilMock.when(() -> GSOAuthUtil.getSigningKey(oauthProps)).thenReturn(rsaPrivateKey);

                        String jwt = GSOAuthUtil.getSignedJWT(oauthProps, widgetClient, authClient, personsV2FeignClient);

                        assertNotNull(jwt);
                        assertTrue(SignedJWT.parse(jwt).getJWTClaimsSet().getClaims().containsKey("client_id"));
                    }
                }
            }
        }
    }

    @Test
    void testGetSignedJWT_WhenExceptionOccurs_ShouldLogAndThrow() {
        try (MockedConstruction<ServiceDelegator> mocked = Mockito.mockConstruction(ServiceDelegator.class,
                (mock, context) -> when(mock.getPersonSessionToken()).thenThrow(new RuntimeException("fail")))) {

            Exception ex = assertThrows(Exception.class, () ->
                    GSOAuthUtil.getSignedJWT(oauthProps, widgetClient, authClient, personsV2FeignClient));

            assertTrue(ex.getMessage().contains("Exception while signing access token"));
        }
    }
    
    @Test
    void testGetSignedJWT_WhenRACFParsingFails_ShouldLogAndContinue() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        IdMapping idMapping = new IdMapping();
        idMapping.setDomain("dc");
        idMapping.setClientId("client123");
        idMapping.setNormalizedClientId("normClient");
        idMapping.setPlatformInternalId("platformId");
        idMapping.setSystemInstanceId("sysId");

        PersonSessionToken pst = new PersonSessionToken();
        pst.setIdMapping(List.of(idMapping));
        pst.setTestCfg("testCfg");

        try (MockedConstruction<ServiceDelegator> mocked = Mockito.mockConstruction(ServiceDelegator.class,
                (mock, context) -> when(mock.getPersonSessionToken()).thenReturn(pst))) {

            try (MockedStatic<RequestContextHolder> contextHolder = mockStatic(RequestContextHolder.class)) {
                ServletRequestAttributes attrs = mock(ServletRequestAttributes.class);
                contextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(attrs);
                when(attrs.getRequest()).thenReturn(request);
                when(request.getHeader(GSAMConstants.COLLEAGUE_SESSION_TOKEN)).thenReturn("mockToken");

                try (MockedStatic<ColleagueSessionToken> tokenStatic = mockStatic(ColleagueSessionToken.class)) {
                    tokenStatic.when(() -> ColleagueSessionToken.parse("mockToken"))
                            .thenThrow(new RuntimeException("Parsing failed"));

                    Map<Object, Object> uceMap = new HashMap<>();
                    uceMap.put(GSAMConstants.IRA_RACF_AUTH_PROFILE_TXT, "racfProfile");
                    Map<Object, Object> configMap = new HashMap<>();
                    configMap.put(GSAMConstants.TEXT_UCE, uceMap);
                    when(widgetClient.getListOfAsset(any())).thenReturn(List.of(configMap));

                    PersonsV2 persons = new PersonsV2();
                    persons.setGlobalPersonIdentifier("globalId");
                    when(personsV2FeignClient.getPersonsV2Response())
                            .thenReturn(new ResponseEntity<>(persons, HttpStatus.OK));

                    try (MockedStatic<GSOAuthUtil> utilMock = mockStatic(GSOAuthUtil.class, CALLS_REAL_METHODS)) {
                        utilMock.when(() -> GSOAuthUtil.getSigningKey(oauthProps)).thenReturn(rsaPrivateKey);

                        String jwt = GSOAuthUtil.getSignedJWT(oauthProps, widgetClient, authClient, personsV2FeignClient);

                        assertNotNull(jwt);
                        assertTrue(SignedJWT.parse(jwt).getJWTClaimsSet().getClaims().containsKey("client_id"));
                    }
                }
            }
        }
    }

    @Test
    void testGetGoldData_WhenExceptionThrown_ShouldLogAndReturnNull() {
        ChannelWidgetConfigurationClient widgetClient = mock(ChannelWidgetConfigurationClient.class);

        when(widgetClient.getListOfAsset(any())).thenThrow(new RuntimeException("Simulated failure"));

        List<Map<Object, Object>> result = invokeGetGoldData(widgetClient);

        assertNull(result); 
    }

    @SuppressWarnings("unchecked")
    private List<Map<Object, Object>> invokeGetGoldData(ChannelWidgetConfigurationClient widgetClient) {
        try {
             Method method = GSOAuthUtil.class.getDeclaredMethod("getGoldData", ChannelWidgetConfigurationClient.class);
            method.setAccessible(true);
            return (List<Map<Object, Object>>) method.invoke(null, widgetClient);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    
}
