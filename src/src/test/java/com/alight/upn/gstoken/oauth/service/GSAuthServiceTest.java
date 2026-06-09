package com.alight.upn.gstoken.oauth.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.alight.upn.gstoken.oauth.config.GSOAuthProperties;
import com.alight.upn.gstoken.oauth.feign.ChannelWidgetConfigurationClient;
import com.alight.upn.gstoken.oauth.feign.PersonAuthorizationFeignClient;
import com.alight.upn.gstoken.oauth.feign.PersonsV2FeignClient;
import com.alight.upn.gstoken.oauth.util.GSAMCommonUtil;
import com.alight.upn.gstoken.oauth.util.GSOAuthUtil;
import com.alight.upn.gstoken.oauth.util.GSTokenUtil;
import com.alight.upn.gstoken.oauth.util.SanitizeUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(SpringExtension.class)
public class GSAuthServiceTest {

    @Spy
    @InjectMocks
    private GSAuthService gsAuthService;

    @Mock private ApplicationContext context;
    @Mock private RestTemplate restTemplate;
    @Mock private GSTokenUtil gsTokenUtil;
    @Mock private ObjectMapper objectMapper;
    @Mock private ChannelWidgetConfigurationClient channelWidgetFeignClient;
    @Mock private PersonAuthorizationFeignClient personAuthorizationFeignClient;
    @Mock private PersonsV2FeignClient personsV2FeignClient;
    @Mock private GSOAuthProperties gsOAuthProperties;
    @Mock private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    public void tearDown() {
        Mockito.framework().clearInlineMocks();
    }

    @Test
    public void testCallGSAuth_Success() {
        String jwtToken = "mock-jwt";
        String authUrl = "https://auth.example.com/token";
        String expectedResponse = "{\"access_token\":\"abc123\"}";

        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getAuthUrl()).thenReturn(authUrl);
        when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
            .thenReturn(new ResponseEntity<>(expectedResponse, HttpStatus.OK));

        ResponseEntity<String> response = gsAuthService.callGSAuth(jwtToken);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(expectedResponse, response.getBody());
    }

    @Test
    public void testCallGSAuth_ThrowsException() {
        String jwtToken = "mock-jwt";
        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getAuthUrl()).thenReturn(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            gsAuthService.callGSAuth(jwtToken);
        });

        assertTrue(exception.getMessage().contains("Error"));
    }

    @Test
    public void testSendRedirectInternal_SuccessfulPlainResponse() throws Exception {
        String proxyEndpoint = "https://proxy.example.com";
        String uri = "/proxy/test";
        String query = "param=value";
        String method = "GET";
        String token = "mock-token";
        byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
        byte[] responseBody = "response-body".getBytes(StandardCharsets.UTF_8);

        HttpHeaders originalHeaders = new HttpHeaders();
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_JSON);
        
     // Mock header names and values
        Vector<String> headerNames = new Vector<>();
        headerNames.add("Content-Type");
        headerNames.add("Authorization");

        when(request.getHeaderNames()).thenReturn(headerNames.elements());
        when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

        when(request.getRequestURI()).thenReturn(uri);
        when(request.getQueryString()).thenReturn(query);
        when(request.getMethod()).thenReturn(method);
        when(request.getHeader(anyString())).thenReturn("header-value");

        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getProxyEndpoint()).thenReturn(proxyEndpoint);
        when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn(token);

        ResponseEntity<byte[]> mockResponse = new ResponseEntity<>(responseBody, responseHeaders, HttpStatus.OK);
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(byte[].class)))
            .thenReturn(mockResponse);

        ResponseEntity<?> result = gsAuthService.sendRedirectInternal(request, body, originalHeaders, false);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody() instanceof String);
    }

    @Test
    public void testSendRedirectInternal_GzipResponseWithNonPdfContentType() throws Exception {
        String proxyEndpoint = "https://proxy.example.com";
        String uri = "/proxy/test";
        String method = "POST";
        String token = "mock-token";
        String originalContent = "compressed-response";

        byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
        byte[] compressedResponse = gsAuthService.compressToGzip(originalContent);

        HttpHeaders originalHeaders = new HttpHeaders();
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set(HttpHeaders.CONTENT_ENCODING, "gzip");
        responseHeaders.set(HttpHeaders.CONTENT_TYPE, "application/json"); 
        
     // Mock header names and values
        Vector<String> headerNames = new Vector<>();
        headerNames.add("Content-Type");
        headerNames.add("Authorization");

        when(request.getHeaderNames()).thenReturn(headerNames.elements());
        when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

        when(request.getRequestURI()).thenReturn(uri);
        when(request.getQueryString()).thenReturn(null);
        when(request.getMethod()).thenReturn(method);
        when(request.getHeader(anyString())).thenReturn("header-value");

        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getProxyEndpoint()).thenReturn(proxyEndpoint);
        when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn(token);

        ResponseEntity<byte[]> mockResponse = new ResponseEntity<>(compressedResponse, responseHeaders, HttpStatus.OK);
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(byte[].class)))
            .thenReturn(mockResponse);

        ResponseEntity<?> result = gsAuthService.sendRedirectInternal(request, body, originalHeaders, false);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody() instanceof byte[]); 

        String decompressed = GSAMCommonUtil.decompressGzipFromBase64Response((byte[]) result.getBody());
        assertEquals(SanitizeUtil.clean(originalContent), decompressed);
    }

    @Test
    public void testSendRedirectInternal_401Retry() throws Exception {
        String proxyEndpoint = "https://proxy.example.com";
        String uri = "/proxy/test";
        String method = "GET";
        byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);

        HttpHeaders originalHeaders = new HttpHeaders();
        HttpHeaders responseHeaders = new HttpHeaders();

     // Mock header names and values
        Vector<String> headerNames = new Vector<>();
        headerNames.add("Content-Type");
        headerNames.add("Authorization");

        when(request.getHeaderNames()).thenReturn(headerNames.elements());
        when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));
        
        when(request.getRequestURI()).thenReturn(uri);
        when(request.getQueryString()).thenReturn(null);
        when(request.getMethod()).thenReturn(method);
        when(request.getHeader(anyString())).thenReturn("header-value");

        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getProxyEndpoint()).thenReturn(proxyEndpoint);
        when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("token");

        ResponseEntity<byte[]> unauthorizedResponse = new ResponseEntity<>(null, responseHeaders, HttpStatus.UNAUTHORIZED);
        ResponseEntity<byte[]> successResponse = new ResponseEntity<>("retry-success".getBytes(), responseHeaders, HttpStatus.OK);

        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(byte[].class)))
            .thenReturn(unauthorizedResponse)
            .thenReturn(successResponse);

        ResponseEntity<?> result = gsAuthService.sendRedirect(request, body, originalHeaders);

        assertEquals(HttpStatus.OK, result.getStatusCode());
    }

    @Test
    public void testSendRedirectInternal_InvalidProxyUrl() {
        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getProxyEndpoint()).thenReturn("http://insecure-url");

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            gsAuthService.sendRedirectInternal(request, "test".getBytes(), new HttpHeaders(), false);
        });

        assertEquals("Insecure target URL configured", exception.getMessage());
    }

    @Test
    public void testSendRedirectInternal_UnsupportedMethod() {
        when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
        when(gsOAuthProperties.getProxyEndpoint()).thenReturn("https://proxy.example.com");
        when(request.getRequestURI()).thenReturn("/proxy/test");
        when(request.getMethod()).thenReturn("TRACE");
    }

	@Test
	public void testGetGSAccessToken_WhenTokenNotInRedis() throws Exception {
		when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn(null);
		when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
		doReturn(new ResponseEntity<>("{\"access_token\":\"new-access-token\"}", HttpStatus.OK)).when(gsAuthService)
				.callGSAuth(anyString());

		String jwtToken = "mock-jwt";
		String accessToken = "new-access-token";
		String responseJson = "{\"access_token\":\"" + accessToken + "\"}";

		mockStatic(GSOAuthUtil.class);
		when(GSOAuthUtil.getSignedJWT(any(), any(), any(), any())).thenReturn(jwtToken);

		ResponseEntity<String> responseEntity = new ResponseEntity<>(responseJson, HttpStatus.OK);
		when(gsAuthService.callGSAuth(jwtToken)).thenReturn(responseEntity);

		String token = gsAuthService.getGSAccessToken(request);

		assertEquals(accessToken, token);
		verify(gsTokenUtil).saveGSAMTokenToRedis(accessToken);
	}
	
	@Test
	public void testCallGSAuth_CatchBlock() {
	    String jwtToken = "mock-jwt";
	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getAuthUrl()).thenReturn("https://auth.example.com");

	    when(restTemplate.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
	        .thenThrow(new RuntimeException("Simulated HTTP error"));

	    RuntimeException exception = assertThrows(RuntimeException.class, () -> {
	        gsAuthService.callGSAuth(jwtToken);
	    });

	    assertTrue(exception.getMessage().contains("Simulated HTTP error"));
	}
	
	@Test
	public void testSendRedirectInternal_GzipDecompressionFails() throws Exception {
	    String proxyEndpoint = "https://proxy.example.com";
	    String uri = "/proxy/test";
	    String method = "POST";
	    byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
	    byte[] invalidGzip = "not-gzip".getBytes(StandardCharsets.UTF_8);

	    HttpHeaders originalHeaders = new HttpHeaders();
	    HttpHeaders responseHeaders = new HttpHeaders();
	    responseHeaders.set(HttpHeaders.CONTENT_ENCODING, "gzip");
	    
	 // Mock header names and values
	    Vector<String> headerNames = new Vector<>();
	    headerNames.add("Content-Type");
	    headerNames.add("Authorization");

	    when(request.getHeaderNames()).thenReturn(headerNames.elements());
	    when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
	    when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

	    when(request.getRequestURI()).thenReturn(uri);
	    when(request.getQueryString()).thenReturn(null);
	    when(request.getMethod()).thenReturn(method);
	    when(request.getHeader(anyString())).thenReturn("header-value");

	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getProxyEndpoint()).thenReturn(proxyEndpoint);
	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("token");

	    ResponseEntity<byte[]> mockResponse = new ResponseEntity<>(invalidGzip, responseHeaders, HttpStatus.OK);
	    when(restTemplate.exchange(any(URI.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(byte[].class)))
	        .thenReturn(mockResponse);

	    ResponseEntity<?> result = gsAuthService.sendRedirectInternal(request, body, originalHeaders, false);

	    assertEquals(HttpStatus.OK, result.getStatusCode());
	    assertTrue(result.getBody() instanceof String); // fallback to plain string
	}
	
	@Test
	public void testGetGSAccessToken_WhenExceptionOccurs_ShouldThrowException() throws Exception {
	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn(null);
	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);

	    mockStatic(GSOAuthUtil.class);
	    when(GSOAuthUtil.getSignedJWT(any(), any(), any(), any()))
	        .thenThrow(new RuntimeException("JWT generation failed"));

	    Exception exception = assertThrows(Exception.class, () -> {
	        gsAuthService.getGSAccessToken(request);
	    });

	    assertEquals("JWT generation failed", exception.getMessage());
	}

	@Test
	public void testSendRedirectInternal_WhenHeaderAdditionFails_ShouldLogError() throws Exception {
	    byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
	    HttpHeaders headers = new HttpHeaders();
	    headers.add("Some-Header", "value");
	    
	 // Mock header names and values
	    Vector<String> headerNames = new Vector<>();
	    headerNames.add("Content-Type");
	    headerNames.add("Authorization");

	    when(request.getHeaderNames()).thenReturn(headerNames.elements());
	    when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
	    when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getProxyEndpoint()).thenReturn("https://valid-endpoint.com");

	    when(request.getRequestURI()).thenReturn("/proxy/test");
	    when(request.getQueryString()).thenReturn("param=value");
	    when(request.getMethod()).thenReturn("GET");

	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("mock-token");

	    ResponseEntity<byte[]> mockResponse = new ResponseEntity<>("response".getBytes(), HttpStatus.OK);
	    when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(byte[].class)))
	        .thenReturn(mockResponse);

	    when(request.getHeader(anyString())).thenThrow(new RuntimeException("Header error"));

	    ResponseEntity<?> response = gsAuthService.sendRedirectInternal(request, body, headers, false);

	    assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	@Test
	public void testSendRedirectInternal_WhenZipExceptionOccurs_ShouldReturnUnsanitizedBody() throws Exception {
	    byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
	    HttpHeaders headers = new HttpHeaders();
	    
	 // Mock header names and values
	    Vector<String> headerNames = new Vector<>();
	    headerNames.add("Content-Type");
	    headerNames.add("Authorization");

	    when(request.getHeaderNames()).thenReturn(headerNames.elements());
	    when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
	    when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getProxyEndpoint()).thenReturn("https://valid-endpoint.com");

	    when(request.getRequestURI()).thenReturn("/proxy/test");
	    when(request.getQueryString()).thenReturn(null);
	    when(request.getMethod()).thenReturn("GET");

	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("mock-token");

	    HttpHeaders responseHeaders = new HttpHeaders();
	    responseHeaders.add(HttpHeaders.CONTENT_ENCODING, "gzip");

	    byte[] invalidGzip = "not-gzip-data".getBytes();

	    ResponseEntity<byte[]> mockResponse = new ResponseEntity<>(invalidGzip, responseHeaders, HttpStatus.OK);
	    when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(byte[].class)))
	        .thenReturn(mockResponse);

	    ResponseEntity<?> response = gsAuthService.sendRedirectInternal(request, body, headers, false);

	    assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	@Test
	public void testSendRedirectInternal_WhenUnexpectedExceptionOccurs_ShouldThrow() throws Exception {
	    byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
	    HttpHeaders headers = new HttpHeaders();
	    
	 // Mock header names and values
	    Vector<String> headerNames = new Vector<>();
	    headerNames.add("Content-Type");
	    headerNames.add("Authorization");

	    when(request.getHeaderNames()).thenReturn(headerNames.elements());
	    when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
	    when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getProxyEndpoint()).thenReturn("https://valid-endpoint.com");

	    when(request.getRequestURI()).thenReturn("/proxy/test");
	    when(request.getQueryString()).thenReturn(null);
	    when(request.getMethod()).thenReturn("GET");

	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("mock-token");

	    when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(byte[].class)))
	        .thenThrow(new RuntimeException("Unexpected error"));

	    Exception exception = assertThrows(RuntimeException.class, () -> {
	        gsAuthService.sendRedirectInternal(request, body, headers, false);
	    });

	    assertEquals("Unexpected error", exception.getMessage());
	}
	
	@Test
	public void testSendRedirectInternal_WhenUnauthorizedThenSuccess_ShouldReturnResponse() throws Exception {
	    byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
	    HttpHeaders headers = new HttpHeaders();
	    
	 // Mock header names and values
	    Vector<String> headerNames = new Vector<>();
	    headerNames.add("Content-Type");
	    headerNames.add("Authorization");

	    when(request.getHeaderNames()).thenReturn(headerNames.elements());
	    when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
	    when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getProxyEndpoint()).thenReturn("https://valid-endpoint.com");

	    when(request.getRequestURI()).thenReturn("/proxy/test");
	    when(request.getQueryString()).thenReturn(null);
	    when(request.getMethod()).thenReturn("GET");

	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("mock-token");

	    HttpClientErrorException unauthorizedException = new HttpClientErrorException(HttpStatus.UNAUTHORIZED);

	    HttpHeaders successHeaders = new HttpHeaders();
	    successHeaders.set(HttpHeaders.CONTENT_TYPE, "text/plain"); // or application/json

	    ResponseEntity<byte[]> successResponse = new ResponseEntity<>(
	        "success".getBytes(StandardCharsets.UTF_8),
	        successHeaders,
	        HttpStatus.OK
	    );

	    when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(byte[].class)))
	        .thenThrow(unauthorizedException) // first call
	        .thenReturn(successResponse);     // retry call

	    ResponseEntity<?> response = gsAuthService.sendRedirectInternal(request, body, headers, false);

	    assertEquals(HttpStatus.OK, response.getStatusCode());

	    if (response.getBody() instanceof byte[]) {
	        assertArrayEquals("success".getBytes(StandardCharsets.UTF_8), (byte[]) response.getBody());
	    } else if (response.getBody() instanceof String) {
	        assertEquals("success", response.getBody());
	    } else {
	        fail("Unexpected response body type: " + response.getBody().getClass());
	    }
	}
	
	@Test
	public void testSendRedirectInternal_WithPdfContentType_ShouldReturnOriginalResponse() throws Exception {
	    byte[] body = "test-body".getBytes(StandardCharsets.UTF_8);
	    byte[] originalResponse = "PDF content".getBytes(StandardCharsets.UTF_8);

	    HttpHeaders originalHeaders = new HttpHeaders();
	    HttpHeaders responseHeaders = new HttpHeaders();
	    responseHeaders.set(HttpHeaders.CONTENT_TYPE, "application/pdf");
	    
	    when(request.getRequestURI()).thenReturn("/proxy/test");
	    when(request.getQueryString()).thenReturn(null);
	    when(request.getMethod()).thenReturn("GET");
	    when(request.getHeader(anyString())).thenReturn("header-value");
	    
	 // Mock header names and values
	    Vector<String> headerNames = new Vector<>();
	    headerNames.add("Content-Type");
	    headerNames.add("Authorization");

	    when(request.getHeaderNames()).thenReturn(headerNames.elements());
	    when(request.getHeaders("Content-Type")).thenReturn(Collections.enumeration(List.of("application/json")));
	    when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer mock-token")));

	    when(context.getBean(GSOAuthProperties.class)).thenReturn(gsOAuthProperties);
	    when(gsOAuthProperties.getProxyEndpoint()).thenReturn("https://proxy.example.com");
	    when(gsTokenUtil.getGSAMTokenFromRedis()).thenReturn("mock-token");

	    ResponseEntity<byte[]> mockResponse = new ResponseEntity<>(originalResponse, responseHeaders, HttpStatus.OK);
	    when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(byte[].class)))
	        .thenReturn(mockResponse);

	    ResponseEntity<?> result = gsAuthService.sendRedirectInternal(request, body, originalHeaders, false);

	    assertEquals(HttpStatus.OK, result.getStatusCode());
	    assertTrue(result.getBody() instanceof byte[]);
	    assertArrayEquals(originalResponse, (byte[]) result.getBody());
	}
	
	@Test
	public void testHandleResponse_DecompressionThrowsException_ShouldTriggerCatchBlock() throws Exception {
	    byte[] body = "request-body".getBytes(StandardCharsets.UTF_8);
	    HttpHeaders originalHeaders = new HttpHeaders();
	    boolean retryAttempted = true;

	    HttpHeaders responseHeaders = new HttpHeaders();
	    responseHeaders.add(HttpHeaders.CONTENT_ENCODING, "gzip");
	    responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json");

	    byte[] responseBody = "invalid-gzip-data".getBytes(StandardCharsets.UTF_8);
	    ResponseEntity<byte[]> response = new ResponseEntity<>(responseBody, responseHeaders, HttpStatus.OK);

	    try (MockedStatic<GSAMCommonUtil> mockedUtil = Mockito.mockStatic(GSAMCommonUtil.class)) {
	        mockedUtil.when(() -> GSAMCommonUtil.decompressGzipFromBase64Response(responseBody))
	                  .thenThrow(new IOException("Decompression failed"));

	        Exception exception = assertThrows(IOException.class, () -> {
	            gsAuthService.handleResponse(request, body, originalHeaders, retryAttempted, response);
	        });

	        assertTrue(exception.getMessage().contains("Decompression failed"));
	    }
	}
}
