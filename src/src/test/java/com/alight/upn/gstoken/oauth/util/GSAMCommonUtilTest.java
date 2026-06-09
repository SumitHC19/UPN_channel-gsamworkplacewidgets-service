package com.alight.upn.gstoken.oauth.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import com.alight.asg.model.token.v1_0.IdMapping;
import com.alight.asg.model.token.v1_0.PersonSessionToken;
import com.alight.asg.service.ServiceDelegator;

@ExtendWith(SpringExtension.class)
public class GSAMCommonUtilTest {

    private static final String TOKEN_NAME = "ACCESSTOKEN";

    @Test
    void testGetRedisCacheKey_success() throws Exception {
        try (MockedConstruction<ServiceDelegator> mocked = mockConstruction(ServiceDelegator.class,
                (mock, context) -> {
                    PersonSessionToken token = new PersonSessionToken();
                    IdMapping idMapping = new IdMapping();
                    idMapping.setDomain("dc1");
                    idMapping.setNormalizedClientId("client123");
                    idMapping.setPlatformInternalId("person456");
                    token.setIdMapping(Arrays.asList(idMapping));
                    when(mock.getPersonSessionToken()).thenReturn(token);
                })) {

            String result = GSAMCommonUtil.getRedisCacheKey(TOKEN_NAME);
            assertTrue(result.contains("GSAM:ACCESSTOKEN:client123:person456"));
        }
    }

    @Test
    void testGetRedisCacheKey_nullPersonSessionToken() throws Exception {
        try (MockedConstruction<ServiceDelegator> mocked = mockConstruction(ServiceDelegator.class,
                (mock, context) -> {
                    when(mock.getPersonSessionToken()).thenReturn(null);
                })) {

            String result = GSAMCommonUtil.getRedisCacheKey(TOKEN_NAME);
            assertFalse(result.contains("GSAM:ACCESSTOKEN")); // partial key
        }
    }

    @Test
    void testGetRedisCacheKey_noIdMapping() throws Exception {
        try (MockedConstruction<ServiceDelegator> mocked = mockConstruction(ServiceDelegator.class,
                (mock, context) -> {
                    PersonSessionToken token = new PersonSessionToken();
                    token.setIdMapping(null);
                    when(mock.getPersonSessionToken()).thenReturn(token);
                })) {

            String result = GSAMCommonUtil.getRedisCacheKey(TOKEN_NAME);
            assertFalse(result.contains("GSAM:ACCESSTOKEN"));
        }
    }

    @Test
    void testGetRedisCacheKey_noDcDomain() throws Exception {
        try (MockedConstruction<ServiceDelegator> mocked = mockConstruction(ServiceDelegator.class,
                (mock, context) -> {
                    PersonSessionToken token = new PersonSessionToken();
                    IdMapping idMapping = new IdMapping();
                    idMapping.setDomain("abc");
                    token.setIdMapping(Collections.singletonList(idMapping));
                    when(mock.getPersonSessionToken()).thenReturn(token);
                })) {

            String result = GSAMCommonUtil.getRedisCacheKey(TOKEN_NAME);
            assertFalse(result.contains("GSAM:ACCESSTOKEN"));
        }
    }

    @Test
    void testGetRedisCacheKey_blankClientIdAndPersonId() throws Exception {
        try (MockedConstruction<ServiceDelegator> mocked = mockConstruction(ServiceDelegator.class,
                (mock, context) -> {
                    PersonSessionToken token = new PersonSessionToken();
                    IdMapping idMapping = new IdMapping();
                    idMapping.setDomain("DC");
                    idMapping.setNormalizedClientId(" ");
                    idMapping.setPlatformInternalId("");
                    token.setIdMapping(Collections.singletonList(idMapping));
                    when(mock.getPersonSessionToken()).thenReturn(token);
                })) {

            String result = GSAMCommonUtil.getRedisCacheKey(TOKEN_NAME);
            assertEquals("GSAM:ACCESSTOKEN", result);
        }
    }
    
    @Test
    void testHttpClientErrorException_withGzipAndNonPdfContentType() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_ENCODING, "gzip");
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");

        byte[] compressedBody = "compressedBase64Data".getBytes(StandardCharsets.UTF_8);

        HttpClientErrorException exception = new HttpClientErrorException(
                HttpStatus.BAD_REQUEST,
                "Bad Request",
                headers,
                compressedBody,
                StandardCharsets.UTF_8
        );

        // Mock decompressGzipFromBase64Response if it's static or move to a service
        String result = GSAMCommonUtil.getReadableMessage(exception);
    }

    @Test
    void testHttpClientErrorException_withGzipAndPdfContentType() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_ENCODING, "gzip");
        headers.add(HttpHeaders.CONTENT_TYPE, "application/pdf");

        byte[] body = "PDF content".getBytes(StandardCharsets.UTF_8);

        HttpClientErrorException exception = new HttpClientErrorException(
                HttpStatus.BAD_REQUEST,
                "Bad Request",
                headers,
                body,
                StandardCharsets.UTF_8
        );

        String result = GSAMCommonUtil.getReadableMessage(exception);
        assertEquals("PDF content", result);
    }

    @Test
    void testHttpClientErrorException_withNonGzipEncoding() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_ENCODING, "identity");
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");

        byte[] body = "Plain error".getBytes(StandardCharsets.UTF_8);

        HttpClientErrorException exception = new HttpClientErrorException(
                HttpStatus.BAD_REQUEST,
                "Bad Request",
                headers,
                body,
                StandardCharsets.UTF_8
        );

        String result = GSAMCommonUtil.getReadableMessage(exception);
        assertEquals("Plain error", result);
    }

    @Test
    void testHttpClientErrorException_withNullContentType() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_ENCODING, "gzip");
        // No content type

        byte[] body = "Fallback error".getBytes(StandardCharsets.UTF_8);

        HttpClientErrorException exception = new HttpClientErrorException(
                HttpStatus.BAD_REQUEST,
                "Bad Request",
                headers,
                body,
                StandardCharsets.UTF_8
        );

        String result = GSAMCommonUtil.getReadableMessage(exception);
    }

    @Test
    void testNonHttpClientErrorException() {
        Exception exception = new RuntimeException("Generic error");
        String result = GSAMCommonUtil.getReadableMessage(exception);
        assertEquals("Generic error", result);
    }

    @Test
    void testExceptionDuringProcessing() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_ENCODING, "gzip");
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");

        // Simulate null body or malformed headers
        HttpClientErrorException exception = new HttpClientErrorException(
                HttpStatus.BAD_REQUEST,
                "Bad Request",
                headers,
                null,
                StandardCharsets.UTF_8
        );

        String result = GSAMCommonUtil.getReadableMessage(exception);
        assertTrue(result.startsWith("Failed to parse error response:"));
    }
    
    @Test
    void testHttpServerErrorException_withGzipAndNonPdfContentType() throws Exception {
        
        String originalMessage = "Server error occurred";
        byte[] compressedBody = compressGzip(originalMessage);

        
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_ENCODING, "gzip");
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        
        HttpServerErrorException exception = HttpServerErrorException.create(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                headers,
                compressedBody,
                StandardCharsets.UTF_8
        );

        
        String result = GSAMCommonUtil.getReadableMessage(exception);
        assertEquals(originalMessage, result);
    }
    
    // Utility method to gzip a string
    private byte[] compressGzip(String str) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipStream = new GZIPOutputStream(byteStream)) {
            gzipStream.write(str.getBytes(StandardCharsets.UTF_8));
        }
        return byteStream.toByteArray();
    }
    
    @Test
    void testDecompressGzipFromBase64Response_validCompressedData() throws IOException {
        String original = "This is a test string";
        byte[] compressed = compressStringToGzip(original);

        String result = GSAMCommonUtil.decompressGzipFromBase64Response(compressed);
        assertEquals(original, result);
    }

    @Test
    void testDecompressGzipFromBase64Response_invalidData_shouldThrowException() {
        byte[] invalidData = "Not GZIP data".getBytes(StandardCharsets.UTF_8);

        assertThrows(IOException.class, () -> {
        	GSAMCommonUtil.decompressGzipFromBase64Response(invalidData);
        });
    }

    // Helper method to compress string to GZIP byte[]
    private byte[] compressStringToGzip(String str) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipStream = new GZIPOutputStream(byteStream)) {
            gzipStream.write(str.getBytes(StandardCharsets.UTF_8));
        }
        return byteStream.toByteArray();
    }
}

