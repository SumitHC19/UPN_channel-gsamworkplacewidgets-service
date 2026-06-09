package com.alight.upn.gstoken.oauth.util;

import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;
import com.aonhewitt.upoint.cache.config.RedisCacheConstants;
import com.aonhewitt.upoint.cache.config.provider.ICache;
import com.aonhewitt.upoint.cache.exception.BaseCacheException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


@Component
public class DistributedSessionCacheRedisUtil {

	@Autowired
	@Qualifier(RedisCacheConstants.SESSION_REDIS_CACHE_OBJECT_PROVIDER)
	private ICache redisSessionCacheObjectProvider;
	
	@Autowired
	public DistributedSessionCacheRedisUtil(@Qualifier(RedisCacheConstants.SESSION_REDIS_CACHE_OBJECT_PROVIDER) ICache redisSessionCacheObjectProvider) {
		this.redisSessionCacheObjectProvider = redisSessionCacheObjectProvider;
	}
	
//	@Autowired
//	@Qualifier(RedisCacheConstants.SESSION_REDIS_CACHE_MAP_PROVIDER)
//	private ICache redisSessionCacheMapProvider;
	@Value("${nextcapital.GSAMCacheTTL:12}")
	private long GSAMCacheTTL;

	public long getGSAMCacheTTL() {
		return GSAMCacheTTL * 60 * 60;
	}

	
	public void setGSAMCacheTTL(long GSAMCacheTTL) {
		this.GSAMCacheTTL = GSAMCacheTTL;
	}

	public void saveObjectInCache(String cachekey, String jwtToken) {
		try {
			redisSessionCacheObjectProvider.save(cachekey, null, jwtToken, getGSAMCacheTTL());
		} catch (BaseCacheException bce) {
			ErrorLogEventHelper.logErrorEvent(DistributedSessionCacheRedisUtil.class.getName(),
					"Exception occured in saving Cached Object",
					"saveObjectInCache(String cachekey, Object obj) method failed", bce, ErrorLogEvent.ERROR_SEVERITY);
		}
	}

	public void saveObjectInCache(String cachekey, String jwtToken, long ttl) throws BaseCacheException {

		try {
			redisSessionCacheObjectProvider.save(cachekey, null, jwtToken, ttl);
		} catch (BaseCacheException bce) {
			ErrorLogEventHelper.logErrorEvent(DistributedSessionCacheRedisUtil.class.getName(),
					"Exception occured in saving Cached Object",
					"saveObjectInCache(String cachekey, Object obj, long ttl) method failed", bce,
					ErrorLogEvent.ERROR_SEVERITY);
		}
	}

	public Object getObjectFromCache(String aCacheKey) throws BaseCacheException {
		return redisSessionCacheObjectProvider.find((aCacheKey), null);
	}

	public void deleteObjectFromCache(String cachekey) {
		try {
			redisSessionCacheObjectProvider.delete(cachekey, null);
		} catch (BaseCacheException bce) {
			ErrorLogEventHelper.logErrorEvent(DistributedSessionCacheRedisUtil.class.getName(),
					"Exception occured in deleting Cache", "deleteObjectFromCache(String cachekey) method failed", bce,
					ErrorLogEvent.ERROR_SEVERITY);
		}
	}

}
