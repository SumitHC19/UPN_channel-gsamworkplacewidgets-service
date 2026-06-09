package com.alight.upn.gstoken.oauth.util;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import com.alight.upn.gstoken.oauth.constant.GSAMConstants;
import com.aonhewitt.exceptions.AHBaseException;
import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.DebugLogEventHelper;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;
import com.aonhewitt.logging.helpers.LogEventUtil;
import com.aonhewitt.upoint.cache.exception.BaseCacheException;

@Component
public class GSTokenUtil {

	private static final String CLASS_NAME = GSTokenUtil.class.getName();

	@Autowired
	@Lazy		// to resolve circular dependency
	private DistributedSessionCacheRedisUtil distributedCacheUtil;

	public String getGSAMTokenFromRedis() throws AHBaseException {
		String gSAMToken = null;
		try {
			String GSAMTokenKey = GSAMCommonUtil.getRedisCacheKey(GSAMConstants.GSAM_ACCESS_TOKEN);

			DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Token key : " + GSAMTokenKey + " found in redis", "getGSAMTokenFromRedis()", LogEventUtil.INFO_SEVERITY);

			gSAMToken = (String) distributedCacheUtil.getObjectFromCache(GSAMTokenKey);

		} catch (IOException e) {
			ErrorLogEventHelper.logErrorEvent(CLASS_NAME,
					"IOException Occured While Fetching getGSAMTokenFromRedis From Cache", "getGSAMTokenFromRedis()", e,
					ErrorLogEvent.ERROR_SEVERITY);

		} catch (BaseCacheException e) {
			ErrorLogEventHelper.logErrorEvent(CLASS_NAME,
					"BaseCacheException Occured While Fetching getGSAMTokenFromRedis From Cache",
					"getGSAMTokenFromRedis()", e, ErrorLogEvent.ERROR_SEVERITY);
		}
		return gSAMToken;
	}

	public void saveGSAMTokenToRedis(String jwtToken) throws AHBaseException {

		if (!jwtToken.isEmpty()) {
			String gSAMTokenCacheKey = null;
			try {
				gSAMTokenCacheKey = GSAMCommonUtil.getRedisCacheKey(GSAMConstants.GSAM_ACCESS_TOKEN);

				DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Token key : " + gSAMTokenCacheKey + " found in redis", "saveGSAMTokenToRedis()", LogEventUtil.INFO_SEVERITY);

				distributedCacheUtil.saveObjectInCache(gSAMTokenCacheKey, jwtToken);
			} catch (IOException e) {
				ErrorLogEventHelper.logErrorEvent(this.getClass().getName(),
						"IOException Occured While saving GSAM Token in Cache", "GSAM Token", e,
						ErrorLogEvent.ERROR_SEVERITY);
			}
		}
	}

	public void removeGSAMTokenFromRedis() throws AHBaseException {
		String gSAMTokenCacheKey = null;
		try {

			gSAMTokenCacheKey = GSAMCommonUtil.getRedisCacheKey(GSAMConstants.GSAM_ACCESS_TOKEN);

			DebugLogEventHelper.logDebugEvent(getClass().getName(), "GSAM Token key : " + gSAMTokenCacheKey + " found in redis", "removeGSAMTokenFromRedis()", LogEventUtil.INFO_SEVERITY);

			distributedCacheUtil.deleteObjectFromCache(gSAMTokenCacheKey);

		} catch (IOException e) {
			ErrorLogEventHelper.logErrorEvent(CLASS_NAME, "IOException Occured While removing GSAM Token from Cache",
					"removeGSAMTokenFromRedis", e, ErrorLogEvent.ERROR_SEVERITY);
		}
	}
}
