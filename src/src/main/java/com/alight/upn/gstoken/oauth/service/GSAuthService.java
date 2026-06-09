package com.alight.upn.gstoken.oauth.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.util.UriComponentsBuilder;

import com.alight.upn.gstoken.oauth.config.GSOAuthProperties;
import com.alight.upn.gstoken.oauth.constant.GSAMConstants;
import com.alight.upn.gstoken.oauth.feign.ChannelWidgetConfigurationClient;
import com.alight.upn.gstoken.oauth.feign.PersonAuthorizationFeignClient;
import com.alight.upn.gstoken.oauth.feign.PersonsV2FeignClient;
import com.alight.upn.gstoken.oauth.util.GSAMCommonUtil;
import com.alight.upn.gstoken.oauth.util.GSOAuthUtil;
import com.alight.upn.gstoken.oauth.util.GSTokenUtil;
import com.alight.upn.gstoken.oauth.util.SanitizeUtil;
import com.aonhewitt.exceptions.AHBaseException;
import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.DebugLogEventHelper;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;
import com.aonhewitt.logging.helpers.LogEventUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Service class
 */
@Component
@RequestScope
public class GSAuthService {

	private static final String CLASS_NAME = GSAuthService.class.getName();

	@Autowired
	private ApplicationContext context;

	@Autowired
	private RestTemplate restTemplate;

	@Autowired
	private GSTokenUtil gsTokenUtil;

	@Autowired
	ObjectMapper objectMapper;

	@Autowired
	private ChannelWidgetConfigurationClient channwlWidgetFeignClient;

	@Autowired
	private PersonAuthorizationFeignClient personAuthorizationFeignClient;

	@Autowired
	private PersonsV2FeignClient personsV2FeignClient;

	/**
	 * Authenticate user
	 * 
	 * @param request
	 * @return
	 * @throws Exception
	 */
	public String getGSAccessToken(HttpServletRequest request) throws Exception {

		GSOAuthProperties oauthProps = context.getBean(GSOAuthProperties.class);

		String accessToken = gsTokenUtil.getGSAMTokenFromRedis(); // check if user has the valid token in Redis
		
		String jwtToken = StringUtils.EMPTY;

		if (StringUtils.isBlank(accessToken)) {
			try {
				DebugLogEventHelper.logDebugEvent(getClass().getName(), "Access token not found in redis", "getGSAccessToken()", LogEventUtil.INFO_SEVERITY);

				jwtToken = GSOAuthUtil.getSignedJWT(oauthProps, channwlWidgetFeignClient,
						personAuthorizationFeignClient, personsV2FeignClient);

				ResponseEntity<String> atRresponse = callGSAuth(jwtToken);

				if (atRresponse.getStatusCode().is2xxSuccessful() && atRresponse.getBody() != null) {
					ObjectMapper mapper = new ObjectMapper();
					JsonNode root = mapper.readTree(atRresponse.getBody());
					accessToken = root.path("access_token").asText();

					if (accessToken != null) {
						DebugLogEventHelper.logDebugEvent(getClass().getName(), "Fresh token saving into redis", "getGSAccessToken()" , LogEventUtil.INFO_SEVERITY);

						gsTokenUtil.saveGSAMTokenToRedis(accessToken); // store new accessToken into Redis
					}
				}

			} catch (Exception e) {
				ErrorLogEventHelper.logErrorEvent(CLASS_NAME, "Exception occurred while creating access token",
						"getOAuthToken()", e, e.getMessage(), ErrorLogEvent.ERROR_SEVERITY);
				throw new Exception(e.getMessage());
			}
		} else {
			DebugLogEventHelper.logDebugEvent(getClass().getName(), "Access token found in redis", "getGSAccessToken()" , LogEventUtil.INFO_SEVERITY);
		}

		return accessToken;
	}

	public ResponseEntity<String> callGSAuth(String jwtToken) {

		HttpMethod httpMethod = HttpMethod.POST;

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		String grantType = URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8);
		String assertion = URLEncoder.encode(jwtToken, StandardCharsets.UTF_8);
		String clientId = URLEncoder.encode("alight_api_client", StandardCharsets.UTF_8);
		String requestBody = "grant_type=" + grantType + "&assertion=" + assertion + "&client_id=" + clientId;
		HttpEntity<String> request = new HttpEntity<String>(requestBody, headers);

		ResponseEntity<String> accessTokenResponse = null;
		try {
			GSOAuthProperties oauthProps = context.getBean(GSOAuthProperties.class);

			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(oauthProps.getAuthUrl());
			String uriString = builder.toUriString();
			DebugLogEventHelper.logDebugEvent(getClass().getName(), "Acess Token URL : " + uriString, "callGSAuth()" , LogEventUtil.INFO_SEVERITY);
			DebugLogEventHelper.logDebugEvent(getClass().getName(), "Access Token Request  : " + request.getBody(), "callGSAuth()" , LogEventUtil.INFO_SEVERITY);
			String inverted = "\"";
			String curl = String.format(
					"curl %s -X POST -H %sContent-Type: application/x-www-form-urlencoded%s --data %s%s%s", uriString,
					inverted, inverted, inverted, URLDecoder.decode(requestBody, StandardCharsets.UTF_8), inverted);
			DebugLogEventHelper.logDebugEvent(getClass().getName(), "Try direct CURL : " + curl, "callGSAuth()" , LogEventUtil.INFO_SEVERITY);
			accessTokenResponse = restTemplate.exchange(uriString, httpMethod, request, String.class);
		} catch (Exception e) {
			ErrorLogEventHelper.logErrorEvent(getClass().getName(), "Error:" + e.getMessage(), "getGSToken()", e, "");
			throw new RuntimeException("Error : " + e.getMessage());
		}

		return accessTokenResponse;

	}

	public ResponseEntity<?> sendRedirect(HttpServletRequest request, byte[] body, HttpHeaders originalHeaders)
			throws Exception {
		return sendRedirectInternal(request, body, originalHeaders, false); // false -> to retry once if get 401 from GS
																			// rest call
	}

    public ResponseEntity<?> sendRedirectInternal(HttpServletRequest request, byte[] body, HttpHeaders originalHeaders, boolean retryAttempted) throws Exception {
        URI targetUri = buildTargetUri(request);
        HttpMethod method = validateHttpMethod(request.getMethod());
        HttpHeaders filteredHeaders = prepareRequestHeaders(originalHeaders, request);
        byte[] sanitizedBody = sanitizeRequestBody(body);
        HttpEntity<byte[]> requestEntity = new HttpEntity<>(sanitizedBody, filteredHeaders);
        
        logRequestDetails(targetUri, method, requestEntity, body);

        try {
            ResponseEntity<byte[]> response = restTemplate.exchange(targetUri, method, requestEntity, byte[].class);
            return handleResponse(request, body, originalHeaders, retryAttempted, response);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED && !retryAttempted) {
                DebugLogEventHelper.logDebugEvent(getClass().getName(), "401 Unauthorized caught in exception. Retrying once after removing token.", "sendRedirectInternal()", LogEventUtil.INFO_SEVERITY);
                removeGSAccessToken();
                return sendRedirectInternal(request, body, originalHeaders, true);
            }
            throw e;
        } catch (Exception e) {
        	String readableMessage = GSAMCommonUtil.getReadableMessage(e);
            ErrorLogEventHelper.logErrorEvent(getClass().getName(), "Unexpected error occurred in GSAM proxy call", "sendRedirectInternal()", e, readableMessage, ErrorLogEvent.ERROR_SEVERITY);
            throw e;
        }
    }

    private URI buildTargetUri(HttpServletRequest request) throws URISyntaxException {
        GSOAuthProperties oauthProps = context.getBean(GSOAuthProperties.class);
        String proxyEndpoint = oauthProps.getProxyEndpoint();

        if (proxyEndpoint == null || !proxyEndpoint.startsWith("https://")) {
            throw new IllegalStateException("Insecure target URL configured");
        }

        String proxyPath = SanitizeUtil.clean(request.getRequestURI().replaceFirst("/proxy", ""));
        String queryString = SanitizeUtil.clean(request.getQueryString());
        return new URI(proxyEndpoint + proxyPath + (queryString != null ? "?" + queryString : ""));
    }

    HttpMethod validateHttpMethod(String methodName) {
        Set<HttpMethod> allowedMethods = Set.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.PATCH);
        HttpMethod method = HttpMethod.valueOf(methodName);
        if (!allowedMethods.contains(method)) {
            throw new IllegalArgumentException("Unsupported or unsafe HTTP method: " + methodName);
        }
        return method;
    }

	private HttpHeaders prepareRequestHeaders(HttpHeaders originalHeaders, HttpServletRequest request)
			throws Exception {
		HttpHeaders filteredHeaders = new HttpHeaders();
		List<String> excludedHeaders = List.of("alightRequestHeader", "alightPersonSessionToken",
				"alightColleagueSessionToken");

		logHeaderComparisionAndCount(originalHeaders, request);

		originalHeaders.forEach((key, values) -> {
			if (!excludedHeaders.contains(key)) {
				filteredHeaders.put(key, values);
			}
		});

		String accessToken = getGSAccessToken(request);
		if (accessToken != null) {
			filteredHeaders.set("Authorization", "Bearer " + accessToken);
			DebugLogEventHelper.logDebugEvent(getClass().getName(), "Token added to headers", "prepareRequestHeaders()",
					LogEventUtil.INFO_SEVERITY);
		}

		return filteredHeaders;
	}

	private void logHeaderComparisionAndCount(HttpHeaders originalHeaders, HttpServletRequest request) {
		// Log original headers and count
	    int originalHeaderCount = originalHeaders.size();
	    DebugLogEventHelper.logDebugEvent(getClass().getName(),
	        "Original Headers Count: " + originalHeaderCount,
	        "logHeaderComparisionAndCount()", LogEventUtil.INFO_SEVERITY);
	    DebugLogEventHelper.logDebugEvent(getClass().getName(),
		        "Original Headers: " + originalHeaders.toString(),
		        "logHeaderComparisionAndCount()", LogEventUtil.INFO_SEVERITY);

	    // Extract request headers
	    Enumeration<String> requestHeaderNames = request.getHeaderNames();
	    Map<String, List<String>> requestHeadersMap = new HashMap<>();
	    while (requestHeaderNames.hasMoreElements()) {
	        String headerName = requestHeaderNames.nextElement();
	        List<String> headerValues = Collections.list(request.getHeaders(headerName));
	        requestHeadersMap.put(headerName, headerValues);
	    }

	    // Log request headers and count
	    int requestHeaderCount = requestHeadersMap.size();
	    DebugLogEventHelper.logDebugEvent(getClass().getName(),
	        "HttpServletRequest Headers Count: " + requestHeaderCount ,
	        "logHeaderComparisionAndCount()", LogEventUtil.INFO_SEVERITY);
	    DebugLogEventHelper.logDebugEvent(getClass().getName(),
		        "HttpServletRequest Headers: " + requestHeadersMap.toString(),
		        "logHeaderComparisionAndCount()", LogEventUtil.INFO_SEVERITY);

	    // Compare headers
	    Set<String> allKeys = new HashSet<>();
	    allKeys.addAll(originalHeaders.keySet());
	    allKeys.addAll(requestHeadersMap.keySet());

	    for (String key : allKeys) {
	        List<String> originalValues = originalHeaders.get(key);
	        List<String> requestValues = requestHeadersMap.get(key);

	        if (originalValues == null) {
	            DebugLogEventHelper.logDebugEvent(getClass().getName(),
	                "Header present in HttpServletRequest but missing in originalHeaders : " + key + " = " + requestValues,
	                "logHeaderComparisionAndCount()", LogEventUtil.WARN_SEVERITY);
	        } else if (requestValues == null) {
	            DebugLogEventHelper.logDebugEvent(getClass().getName(),
	                "Header present in originalHeaders but missing in HttpServletRequest : " + key + " = " + originalValues,
	                "logHeaderComparisionAndCount()", LogEventUtil.WARN_SEVERITY);
	        } else if (!originalValues.equals(requestValues)) {
	            DebugLogEventHelper.logDebugEvent(getClass().getName(),
	                "Header value mismatch for key '" + key + "': originalHeaders=" + originalValues + ", HttpServletRequest=" + requestValues,
	                "logHeaderComparisionAndCount()", LogEventUtil.WARN_SEVERITY);
	        }
	    }
	}

    private byte[] sanitizeRequestBody(byte[] body) {
        String bodyString = new String(body, StandardCharsets.UTF_8);
        String sanitizedBodyString = SanitizeUtil.clean(bodyString);
        return sanitizedBodyString.getBytes(StandardCharsets.UTF_8);
    }

   private void logRequestDetails(URI targetUri, HttpMethod method, HttpEntity<byte[]> requestEntity, byte[] originalBody) throws JsonProcessingException {
       DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Request : targetUri : " + targetUri, "sendRedirectInternal()", LogEventUtil.INFO_SEVERITY);
       DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Request : method : " + method, "sendRedirectInternal()", LogEventUtil.INFO_SEVERITY);
       DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Request : headers : " + requestEntity.getHeaders(), "sendRedirectInternal()", LogEventUtil.INFO_SEVERITY);
       DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Request : original body : " + new String(originalBody, StandardCharsets.UTF_8), "sendRedirectInternal()", LogEventUtil.INFO_SEVERITY);
       DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Request : sanitized body : " + objectMapper.writeValueAsString(requestEntity.getBody()), "sendRedirectInternal()", LogEventUtil.INFO_SEVERITY);
       DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Request : IP Address : " + restTemplate.getForObject("https://api.ipify.org", String.class), "sendRedirectInternal()" , LogEventUtil.INFO_SEVERITY);
   }

	ResponseEntity<?> handleResponse(HttpServletRequest request, byte[] body, HttpHeaders originalHeaders, boolean retryAttempted, ResponseEntity<byte[]> response) throws Exception
	{
		HttpStatusCode status = response.getStatusCode();
        HttpHeaders responseHeaders = response.getHeaders();
        byte[] originalRes = response.getBody();

        if (HttpStatus.UNAUTHORIZED.equals(status)) {
            if (!retryAttempted) {
                DebugLogEventHelper.logDebugEvent(getClass().getName(), "401 Unauthorized received. Retrying once after removing token.", "handleResponse()", LogEventUtil.INFO_SEVERITY);
                removeGSAccessToken();
                return sendRedirectInternal(request, body, originalHeaders, true);
            } else {
                DebugLogEventHelper.logDebugEvent(getClass().getName(), "401 Unauthorized received again. No further retries.", "handleResponse()", LogEventUtil.INFO_SEVERITY);
            }
        }

        HttpHeaders newResponseHeaders = enrichResponseHeaders(responseHeaders, request);
        logResponseDetails(status, responseHeaders, originalRes);

        String encoding = responseHeaders.getFirst(HttpHeaders.CONTENT_ENCODING);
        String contentType = responseHeaders.getFirst(HttpHeaders.CONTENT_TYPE);

        try {
            if ("gzip".equalsIgnoreCase(encoding) && contentType != null && !contentType.toLowerCase().contains("application/pdf")) {
                String decompressedBody = GSAMCommonUtil.decompressGzipFromBase64Response(originalRes);
                String sanitizedResBodyString = SanitizeUtil.clean(decompressedBody);
                byte[] sanitizedResBodyBytes = compressToGzip(sanitizedResBodyString);
                return new ResponseEntity<>(sanitizedResBodyBytes, newResponseHeaders, status);
            } else if (contentType != null && contentType.toLowerCase().contains("application/pdf")) {
                return new ResponseEntity<>(originalRes, newResponseHeaders, status);
            } else {
                String resBody = SanitizeUtil.clean(new String(originalRes, StandardCharsets.UTF_8));
                return new ResponseEntity<>(resBody, newResponseHeaders, status);
            }
		}
		catch (Exception e)
		{
			String readableMessage = GSAMCommonUtil.getReadableMessage(e);
			ErrorLogEventHelper.logErrorEvent(getClass().getName(), "Unexpected error occurred in GSAM proxy call", "sendRedirectInternal()", e, readableMessage, ErrorLogEvent.ERROR_SEVERITY);
			throw e;
        }

    }

	HttpHeaders enrichResponseHeaders(HttpHeaders responseHeaders, HttpServletRequest request)
	{
        HttpHeaders newHeaders = new HttpHeaders();
        responseHeaders.forEach((key, values) -> values.forEach(value -> newHeaders.add(key, value)));

        try {
            newHeaders.add("alightRequestHeader", request.getHeader(GSAMConstants.ALIGHT_REQUEST_HEADER));
            newHeaders.add("alightPersonSessionToken", request.getHeader(GSAMConstants.PERSON_SESSION_TOKEN));
            newHeaders.add("alightColleagueSessionToken", request.getHeader(GSAMConstants.COLLEAGUE_SESSION_TOKEN));
            newHeaders.add("Access-Control-Expose-Headers", "Access-Control-Allow-Origin");

            String origin = request.getHeader("Origin");
            if (origin != null && !origin.isEmpty()) {
                newHeaders.add("Access-Control-Allow-Origin", origin);
            }
        } catch (Exception e) {
            ErrorLogEventHelper.logErrorEvent(getClass().getName(), "Error while adding alight headers to proxy responseHeaders.", "enrichResponseHeaders()", e, e.getMessage(), ErrorLogEvent.ERROR_SEVERITY);
        }

        return newHeaders;
    }

	void logResponseDetails(HttpStatusCode status, HttpHeaders headers, byte[] body) throws JsonProcessingException
	{
        DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Response : status code : " + status, "handleResponse()", LogEventUtil.INFO_SEVERITY);
        DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Response : headers : " + headers, "handleResponse()", LogEventUtil.INFO_SEVERITY);
        DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Response : body : " + objectMapper.writeValueAsString(body), "handleResponse()", LogEventUtil.INFO_SEVERITY);
	}

	public void removeGSAccessToken() throws AHBaseException
	{
		gsTokenUtil.removeGSAMTokenFromRedis(); // removed the access token from the redis
	}

	public byte[] compressToGzip(String input) throws IOException {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		try (GZIPOutputStream gzipStream = new GZIPOutputStream(byteStream)) {
			gzipStream.write(input.getBytes(StandardCharsets.UTF_8));
		}
		return byteStream.toByteArray();
	}

}
