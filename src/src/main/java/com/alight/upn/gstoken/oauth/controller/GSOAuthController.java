package com.alight.upn.gstoken.oauth.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.alight.upn.gstoken.oauth.service.GSAuthService;
import com.alight.upn.gstoken.oauth.util.GSAMCommonUtil;
import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class GSOAuthController {

	@Autowired
	private GSAuthService oauthService;

	@RequestMapping(path = "/proxy/**", method = { RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE,
			RequestMethod.PATCH })
	public ResponseEntity<?> proxyRequest(HttpServletRequest request, @RequestBody(required = false) byte[] body,
			@RequestHeader HttpHeaders headers) {
		try {
			// Forward the request to the service
			return oauthService.sendRedirect(request, body != null ? body : new byte[0], headers);
		} catch (Exception e) {
			String readableMessage = GSAMCommonUtil.getReadableMessage(e);
			ErrorLogEventHelper.logErrorEvent(GSOAuthController.class.getName(), "Error while processing poxy request.",
					"proxyRequest()", e, readableMessage, ErrorLogEvent.ERROR_SEVERITY);
			return new ResponseEntity<>(readableMessage,HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@GetMapping(value = "/nextcapital/auth")
	public ResponseEntity<Map<String, String>> getAccessToken(HttpServletRequest request) {
		try {
			String accessToken = oauthService.getGSAccessToken(request);
			Map<String, String> response = new HashMap<>();
			response.put("accessToken", accessToken);
			return ResponseEntity.ok(response);
		} catch (Exception e) {
			ErrorLogEventHelper.logErrorEvent(GSOAuthController.class.getName(), "Error while retrieving access token.",
					"getAccessToken()", e, e.getMessage(), ErrorLogEvent.ERROR_SEVERITY);
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@DeleteMapping(value = "/nextcapital/auth/token")
	public ResponseEntity<Void> removeAccessToken() {
		try {
			oauthService.removeGSAccessToken();
			return ResponseEntity.noContent().build(); // 204 No Content
		} catch (Exception e) {
			ErrorLogEventHelper.logErrorEvent(GSOAuthController.class.getName(), "Error while removing access token.", "removeAccessToken()", e, e.getMessage(), ErrorLogEvent.ERROR_SEVERITY);
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

}
