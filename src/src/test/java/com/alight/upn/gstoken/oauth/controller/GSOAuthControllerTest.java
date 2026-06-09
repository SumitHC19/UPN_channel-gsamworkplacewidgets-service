package com.alight.upn.gstoken.oauth.controller;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.http.*;
import org.springframework.mock.web.MockHttpServletRequest;
import com.alight.upn.gstoken.oauth.service.GSAuthService;

@ExtendWith(SpringExtension.class)
public class GSOAuthControllerTest {

	@Mock
	private GSAuthService oauthService;
	
	@InjectMocks
	private GSOAuthController gsoAuthController;
	
	@Mock
    private HttpServletRequest request;
	
	@BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testProxyRequest_SuccessWithBody() throws Exception {
       
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/proxy/test");
        byte[] body = "test-body".getBytes();
        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<String> expectedResponse = new ResponseEntity<>("Success", HttpStatus.OK);
        when(oauthService.sendRedirect(any(), eq(body), eq(headers)))
            .thenReturn((ResponseEntity) expectedResponse);    	        
        ResponseEntity<?> response = gsoAuthController.proxyRequest(request, body, headers);	        
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Success", response.getBody());
    }

    @Test
    public void testProxyRequest_SuccessWithNullBody() throws Exception {       
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/proxy/test");
        HttpHeaders headers = new HttpHeaders();
        byte[] emptyBody = new byte[0];
        ResponseEntity<String> expectedResponse = new ResponseEntity<>("No Body", HttpStatus.OK);
        when(oauthService.sendRedirect(any(), eq(emptyBody), eq(headers))).thenReturn((ResponseEntity)expectedResponse);	      
        ResponseEntity<?> response = gsoAuthController.proxyRequest(request, null, headers);	        
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("No Body", response.getBody());
    }

    @Test
    public void testProxyRequest_ExceptionThrown() throws Exception {       
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/proxy/test");
        byte[] body = "error".getBytes();
        HttpHeaders headers = new HttpHeaders();
        when(oauthService.sendRedirect(any(), eq(body), eq(headers)))
                .thenThrow(new RuntimeException("Service failure"));      
        ResponseEntity<?> response = gsoAuthController.proxyRequest(request, body, headers);        
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Service failure", response.getBody());
    }
    
    @Test
    public void testGetAccessToken_Success() throws Exception {       
        String mockToken = "mocked-token";
        when(oauthService.getGSAccessToken(request)).thenReturn(mockToken);      
        ResponseEntity<Map<String, String>> response = gsoAuthController.getAccessToken(request);        
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody());
        assertEquals("mocked-token", response.getBody().get("accessToken"));
    }

    @Test
    public void testGetAccessToken_ExceptionThrown() throws Exception {       
        when(oauthService.getGSAccessToken(request)).thenThrow(new RuntimeException("Token error"));     
        ResponseEntity<Map<String, String>> response = gsoAuthController.getAccessToken(request);        
        assertEquals(500, response.getStatusCodeValue());
        assertNull(response.getBody());
    }
    
    @Test
    public void testRemoveAccessToken_Success() throws Exception {	       
        doNothing().when(oauthService).removeGSAccessToken();	      
        ResponseEntity<Void> response = gsoAuthController.removeAccessToken();	        
        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    public void testRemoveAccessToken_ExceptionThrown() throws Exception {	        
        doThrow(new RuntimeException("Removal failed")).when(oauthService).removeGSAccessToken();
        ResponseEntity<Void> response = gsoAuthController.removeAccessToken();
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNull(response.getBody());
    }
	
}
