package com.alight.upn.gstoken.oauth.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.zip.GZIPInputStream;

import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import com.alight.asg.model.token.v1_0.IdMapping;
import com.alight.asg.model.token.v1_0.PersonSessionToken;
import com.alight.asg.service.ServiceDelegator;
import com.alight.upn.gstoken.oauth.constant.GSAMConstants;
import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;


@Component
public class GSAMCommonUtil {

	private static final String CLASS_NAME = GSAMCommonUtil.class.getName();

	public static String getRedisCacheKey(String tokenName)
			throws JsonParseException, JsonMappingException, IOException {

		// GSAM:ACCESSTOKEN:clientId:personinternalid
		StringBuffer key = new StringBuffer();
		try {

			String requestkey = getKey();
			key.append(GSAMConstants.REDIS_KEY_GSAM);
			key.append(tokenName);
			key.append(requestkey); // clientId+personInternalId
			return key.toString();
		} catch (Exception e) {
			ErrorLogEventHelper.logErrorEvent(CLASS_NAME, "Exception occured in getRedisCacheKey",
					"getRedisCacheKey(String tokenName) method failed", e, ErrorLogEvent.ERROR_SEVERITY);
		}

		return key.toString();
	}

	private static String getKey() throws Exception {

		StringBuffer key = new StringBuffer(180);

		ServiceDelegator sdg;
		sdg = new ServiceDelegator();

		PersonSessionToken personSessionToken = sdg.getPersonSessionToken();
		if (personSessionToken == null || personSessionToken.getIdMapping() == null) {
			throw new Exception("PersonSesstionToken invalid");
		}
		Optional<IdMapping> idMapping = personSessionToken.getIdMapping().stream()
				.filter(idm -> idm.getDomain().contains("dc") || idm.getDomain().contains("DC")).findFirst();
		if (!idMapping.isPresent()) {
			throw new Exception("No DC Domain found");
		}

		String clientId = idMapping.get().getNormalizedClientId();
		if (StringUtils.isNotBlank(clientId)) {
			key.append(GSAMConstants.COLON);
			key.append(clientId);
		}

		String personInternalId = idMapping.get().getPlatformInternalId();
		if (StringUtils.isNotBlank(personInternalId)) {
			key.append(GSAMConstants.COLON);
			key.append(personInternalId);
		}

		return key.toString();
	}
	
	public static String getReadableMessage(Exception e) {
		String readableMessage = "";
		try
		{
			if (e instanceof HttpClientErrorException || e instanceof HttpServerErrorException) {
                byte[] errorBody;
                String encoding;
                String contentType;

                if (e instanceof HttpClientErrorException) {
                    HttpClientErrorException ex = (HttpClientErrorException) e;
                    errorBody = ex.getResponseBodyAsByteArray();
                    encoding = ex.getResponseHeaders().getFirst(HttpHeaders.CONTENT_ENCODING);
                    contentType = ex.getResponseHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
                } else {
                    HttpServerErrorException ex = (HttpServerErrorException) e;
                    errorBody = ex.getResponseBodyAsByteArray();
                    encoding = ex.getResponseHeaders().getFirst(HttpHeaders.CONTENT_ENCODING);
                    contentType = ex.getResponseHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
                }

                boolean isPdf = contentType != null && contentType.toLowerCase().contains("application/pdf");

                if ("gzip".equalsIgnoreCase(encoding) && !isPdf)
				{
					readableMessage = decompressGzipFromBase64Response(errorBody);
				}
				else
				{
					readableMessage = new String(errorBody, StandardCharsets.UTF_8);
				}
			}
			else
			{
				readableMessage = e.getMessage();
			}
		}
		catch (Exception ex)
		{
			readableMessage = "Failed to parse error response: " + ex.getMessage();
		}
		return readableMessage;
	}
	
	public static String decompressGzipFromBase64Response(byte[] bs) throws IOException
	{
//		byte[] compressedBytes = Base64.getDecoder().decode(bs.getBody());
		try (GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(bs));
				ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			byte[] buffer = new byte[1024];
			int len;
			while ((len = gzipInputStream.read(buffer)) != -1) {
				out.write(buffer, 0, len);
			}
			return out.toString(StandardCharsets.UTF_8);
		}
	}
}
