package com.alight.upn.gstoken.oauth.util;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import com.aonhewitt.upoint.cache.config.provider.ICache;
import com.aonhewitt.upoint.cache.exception.BaseCacheException;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
public class DistributedSessionCacheRedisUtilTest {
	
	
		@InjectMocks
		private DistributedSessionCacheRedisUtil distributedSessionCacheRedisUtil;

		@Mock(name = "redisSessionCacheObjectProvider")
		private ICache sessionRedisCacheObjectProvider;

		
		@Test
		public void saveObjectInCacheTest()
		{

			distributedSessionCacheRedisUtil.saveObjectInCache("", new Object().toString());
		}

		@Test
		public void saveObjectInCacheNullTest() throws BaseCacheException
		{

			distributedSessionCacheRedisUtil.saveObjectInCache("", null);
		}

		@Test
		public void saveObjectInCacheWithParamTest() throws BaseCacheException
		{
			Mockito.doNothing().when(sessionRedisCacheObjectProvider).save("CacheKey", null, "CacheValue", 900);
			distributedSessionCacheRedisUtil.saveObjectInCache("cacheKey", "CacheKey", 12113121);

			Mockito.doThrow(new BaseCacheException("Exception occured in saving Cached Object")).when(sessionRedisCacheObjectProvider).save(null, null, null, 900);
			distributedSessionCacheRedisUtil.saveObjectInCache(null, null, 900);
		}

		@Test
		public void saveObjectInCacheWithParamExceptionTest() throws BaseCacheException
		{
			Mockito.doThrow(new BaseCacheException("Exception occured in saving Cached Object")).when(sessionRedisCacheObjectProvider).save(null, null, null, 0);

			distributedSessionCacheRedisUtil.saveObjectInCache("", null);
		}

		@Test
		public void getObjectFromCacheTest() throws BaseCacheException
		{
			distributedSessionCacheRedisUtil.getObjectFromCache("");
		}

		@Test
		public void getDeleteObjectCacheTest() throws BaseCacheException
		{
			distributedSessionCacheRedisUtil.deleteObjectFromCache("");
		}

		@Test
		public void getDeleteObjectCacheExceptionTest() throws BaseCacheException
		{
			Mockito.doThrow(new BaseCacheException("Exception occured in saving Cached Object")).when(sessionRedisCacheObjectProvider).delete("", null);

			distributedSessionCacheRedisUtil.deleteObjectFromCache("");
		}

		@Test
	    void testSetGSAMCacheTTL() throws Exception {
	        long expectedTTL = 7200L;

	        distributedSessionCacheRedisUtil.setGSAMCacheTTL(expectedTTL);

	        // Use reflection to verify the private field
	        Field field = DistributedSessionCacheRedisUtil.class.getDeclaredField("GSAMCacheTTL");
	        field.setAccessible(true);
	        long actualTTL = (long) field.get(distributedSessionCacheRedisUtil);

	        assertEquals(expectedTTL, actualTTL, "GSAMCacheTTL should be set correctly");
	    }


}
