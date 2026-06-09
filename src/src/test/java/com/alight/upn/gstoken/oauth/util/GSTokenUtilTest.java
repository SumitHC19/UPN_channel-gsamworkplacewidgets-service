package com.alight.upn.gstoken.oauth.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import com.aonhewitt.upoint.cache.exception.BaseCacheException;

@ExtendWith(MockitoExtension.class)
public class GSTokenUtilTest {

	@Mock
	private DistributedSessionCacheRedisUtil distributedCacheUtil;

	@InjectMocks
	private GSTokenUtil gstokenUtil;

	private static final String TOKEN_KEY = "GSAM_ACCESS_TOKEN_KEY";
	private static final String TOKEN_VALUE = "mocked-jwt-token";

	private static MockedStatic<GSAMCommonUtil> mockedStatic;

	@BeforeAll
	static void initStaticMock() {
		mockedStatic = mockStatic(GSAMCommonUtil.class);
		mockedStatic.when(() -> GSAMCommonUtil.getRedisCacheKey(anyString())).thenReturn(TOKEN_KEY);
	}

	@AfterAll
	static void closeStaticMock() {
		mockedStatic.close();
	}

	@Test
	void testGetGSAMTokenFromRedis_Success() throws Exception {
		when(distributedCacheUtil.getObjectFromCache(TOKEN_KEY)).thenReturn(TOKEN_VALUE);

		String result = gstokenUtil.getGSAMTokenFromRedis();

		assertEquals(TOKEN_VALUE, result);
		verify(distributedCacheUtil).getObjectFromCache(TOKEN_KEY);
	}

	@Test
	void testGetGSAMTokenFromRedis_BaseCacheException() throws Exception {
		when(distributedCacheUtil.getObjectFromCache(TOKEN_KEY)).thenThrow(new BaseCacheException("Cache Error"));

		String token = gstokenUtil.getGSAMTokenFromRedis();

		assertNull(token);
	}

	@Test
	void testGetGSAMTokenFromRedis_RuntimeException() throws Exception {
		when(distributedCacheUtil.getObjectFromCache(TOKEN_KEY)).thenThrow(new RuntimeException("Unexpected error"));

		RuntimeException exception = assertThrows(RuntimeException.class, () -> {
			gstokenUtil.getGSAMTokenFromRedis();
		});

		assertEquals("Unexpected error", exception.getMessage());
	}

	@Test
	void testSaveGSAMTokenToRedis_Success() throws Exception {
		doNothing().when(distributedCacheUtil).saveObjectInCache(TOKEN_KEY, TOKEN_VALUE);

		assertDoesNotThrow(() -> gstokenUtil.saveGSAMTokenToRedis(TOKEN_VALUE));
		verify(distributedCacheUtil).saveObjectInCache(TOKEN_KEY, TOKEN_VALUE);
	}

	@Test
	void testSaveGSAMTokenToRedis_EmptyToken() throws Exception {
		assertDoesNotThrow(() -> gstokenUtil.saveGSAMTokenToRedis(""));
		verify(distributedCacheUtil, never()).saveObjectInCache(anyString(), anyString());
	}

	@Test
	void testSaveGSAMTokenToRedis_RuntimeException() throws Exception {
		doThrow(new RuntimeException("Unexpected error")).when(distributedCacheUtil).saveObjectInCache(TOKEN_KEY,
				TOKEN_VALUE);

		RuntimeException exception = assertThrows(RuntimeException.class, () -> {
			gstokenUtil.saveGSAMTokenToRedis(TOKEN_VALUE);
		});

		assertEquals("Unexpected error", exception.getMessage());
	}

	@Test
	void testRemoveGSAMTokenFromRedis_Success() throws Exception {
		doNothing().when(distributedCacheUtil).deleteObjectFromCache(TOKEN_KEY);

		assertDoesNotThrow(() -> gstokenUtil.removeGSAMTokenFromRedis());
		verify(distributedCacheUtil).deleteObjectFromCache(TOKEN_KEY);
	}

	@Test
	void testRemoveGSAMTokenFromRedis_RuntimeException() throws Exception {
		doThrow(new RuntimeException("Unexpected error")).when(distributedCacheUtil).deleteObjectFromCache(TOKEN_KEY);

		RuntimeException exception = assertThrows(RuntimeException.class, () -> {
			gstokenUtil.removeGSAMTokenFromRedis();
		});

		assertEquals("Unexpected error", exception.getMessage());
	}
}
