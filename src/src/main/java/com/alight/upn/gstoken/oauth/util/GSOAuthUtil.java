package com.alight.upn.gstoken.oauth.util;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.alight.asg.model.token.v1_0.ColleagueSessionToken;
import com.alight.asg.model.token.v1_0.IdMapping;
import com.alight.asg.model.token.v1_0.PersonSessionToken;
import com.alight.asg.service.ServiceDelegator;
import com.alight.cloud.data.store.util.DockerSecretsUtil;
import com.alight.portal.core.udp.v2.dto.person.PersonsV2;
import com.alight.upn.gstoken.oauth.config.GSOAuthProperties;
import com.alight.upn.gstoken.oauth.constant.GSAMConstants;
import com.alight.upn.gstoken.oauth.feign.ChannelWidgetConfigurationClient;
import com.alight.upn.gstoken.oauth.feign.PersonAuthorizationFeignClient;
import com.alight.upn.gstoken.oauth.feign.PersonsV2FeignClient;
import com.aonhewitt.beans.ExprKey;
import com.aonhewitt.beans.GenericRequestBean;
import com.aonhewitt.beans.TextKey;
import com.aonhewitt.logging.events.ErrorLogEvent;
import com.aonhewitt.logging.helpers.DebugLogEventHelper;
import com.aonhewitt.logging.helpers.ErrorLogEventHelper;
import com.aonhewitt.logging.helpers.LogEventUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.http.HttpServletRequest;


public class GSOAuthUtil {

	private static final String CLASS_NAME = GSOAuthUtil.class.getName();
	
	/**
	 * Reads text secret line and returns as string.
	 * 
	 * @param name
	 * @return
	 * @throws AlightZuulException
	 */
	public static String getSecret(String name, String lifecycle) throws Exception {
        Map<String, String> secrets = DockerSecretsUtil.load();        
        String secret = secrets.get(name);
        if (secret == null) {

			throw new Exception("Secret " + name + " not found");
        }
        return secret.trim();
	}

	/**
	 * Gets Signed JWT Token.
	 * 
	 * @param channwlWidgetFeignClient
	 * @param personAuthorizationFeignClient
	 * @param brokerUserId
	 * @param tokenTimeout
	 * @return
	 * @throws Exception
	 * @throws IOException
	 * @throws JsonProcessingException
	 */
	public static String getSignedJWT(GSOAuthProperties oauthProps,
			ChannelWidgetConfigurationClient channwlWidgetFeignClient,
			PersonAuthorizationFeignClient personAuthorizationFeignClient, PersonsV2FeignClient personsV2FeignClient)
			throws Exception
	{
		try
		{
			ServiceDelegator sdg;
			sdg = new ServiceDelegator();

			PersonSessionToken personSessionToken = sdg.getPersonSessionToken();
			if(personSessionToken==null || personSessionToken.getIdMapping()==null) {
				throw new Exception("PersonSesstionToken invalid");
			}
			Optional<IdMapping> idMapping = personSessionToken.getIdMapping().stream()
					.filter(idm -> idm.getDomain().contains("dc") || idm.getDomain().contains("DC")).findFirst();
			if(!idMapping.isPresent()) {
				throw new Exception("No DC Domain found");
			}
			String clientId = idMapping.get().getClientId();
			String normalizedClientId = idMapping.get().getNormalizedClientId();
			// Get the current time
			LocalDateTime now = LocalDateTime.now();
			LocalDateTime futureTime = now.plus(12, ChronoUnit.HOURS);
			long unixTimestamp = futureTime.atZone(ZoneId.systemDefault()).toEpochSecond();
			Date expirationTime = Date.from(Instant.ofEpochSecond(unixTimestamp));

			String sourceTestCfg = StringUtils.EMPTY;
			String udptestcfg = StringUtils.EMPTY;
			
			if (!"PROD".equalsIgnoreCase(oauthProps.getLifecycle())
					&& StringUtils.isNotBlank(idMapping.get().getSourceTestCfg())) {
				sourceTestCfg = idMapping.get().getSourceTestCfg();
			}

			if (!"PROD".equalsIgnoreCase(oauthProps.getLifecycle())
					&& StringUtils.isNotBlank(personSessionToken.getTestCfg())) {
				udptestcfg = personSessionToken.getTestCfg();
			}
			
			String advisorId = StringUtils.EMPTY;
			
			HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
			
			try
			{
				String cTokenFromHeader = request != null ? request.getHeader(GSAMConstants.COLLEAGUE_SESSION_TOKEN) : null;

				if (Objects.nonNull(cTokenFromHeader))
				{
					List<Map<Object, Object>> goldDataList = getGoldData(channwlWidgetFeignClient);
					String racfProfile = getUCETextValue(goldDataList.get(0), GSAMConstants.IRA_RACF_AUTH_PROFILE_TXT);
					ColleagueSessionToken cToken = ColleagueSessionToken.parse(cTokenFromHeader);
					String racfID = cToken.getColleagueSessionMapEntry(GSAMConstants.CRED_RACF_ID);
					cTokenFromHeader = cTokenFromHeader.replaceAll(racfID, racfID.toUpperCase());
					boolean isECSAdmin = getExprValue(goldDataList, GSAMConstants.IS_ECS_ADMIN);
					if (isECSAdmin) {
					ResponseEntity<String> racfAuthorize = personAuthorizationFeignClient
							.isRACFAuthorized(cTokenFromHeader, racfProfile);
					
					if (racfAuthorize.getStatusCode().equals(HttpStatus.OK))
					{
						advisorId = racfID.toUpperCase();
					}
					}
				}
			}
			catch (Exception e)
			{
				ErrorLogEventHelper.logErrorEvent(GSOAuthUtil.class.getName(), e.getMessage(), "Error occurred while fetching racf_id ", e, "", ErrorLogEvent.ERROR_SEVERITY);
			}
			
			Object globalPersonIdentifier = getGlobalPersonIdentifier(personsV2FeignClient);
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.issuer("alight_api_client")
					.audience("alight_api")
					.subject("placeholder")
					.expirationTime(expirationTime)
					.claim("saml_subject", globalPersonIdentifier)
//					.claim("gsam_id", "16399636")
					.claim("global_person_id", globalPersonIdentifier)
					.claim("platform_internal_id", idMapping.get().getPlatformInternalId())
					.claim("client_id", clientId)
					.claim("system_instance_id", idMapping.get().getSystemInstanceId())
					.claim("advisor_id", advisorId)
					.claim("mfa", false)
					.claim("user_context", "workplace")
					.claim("test_cfg", udptestcfg)
					.claim("test_cfg_map", sourceTestCfg)
					.claim("plan_provider_id", "alight")
					.claim("normalized_client_id", normalizedClientId)
					.build();
			

			// Convert claims to a Map for logging
			Map<String, Object> claimsMap = claimsSet.getClaims();

			DebugLogEventHelper.logDebugEvent(GSOAuthUtil.class.getName(), "JWT Claims Set: " + claimsMap.toString(), "getSignedJWT()", LogEventUtil.INFO_SEVERITY);

			// Prepare JWT with claims set
			SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
			PrivateKey privateKey = getSigningKey(oauthProps);
			JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
			signedJWT.sign(signer);
			return signedJWT.serialize();
		}
		catch (Exception e)
		{
			ErrorLogEventHelper.logErrorEvent(CLASS_NAME, "Exception while signing access token", "getSignedJWT()", e,
					"", ErrorLogEvent.ERROR_SEVERITY);
			throw new Exception("Exception while signing access token " + e.getMessage());
		}
	}
	
	private static String getGlobalPersonIdentifier(PersonsV2FeignClient personsV2FeignClient) {
		ResponseEntity<PersonsV2> personsV2Response = personsV2FeignClient.getPersonsV2Response();
		PersonsV2 body = personsV2Response.getBody();
		if (body != null) {
			return body.getGlobalPersonIdentifier();
		}
		return StringUtils.EMPTY;
	}

	private static List<Map<Object, Object>> getGoldData(ChannelWidgetConfigurationClient widgetClient) {
		List<Map<Object, Object>> responseData = null;
		try
		{
			List<TextKey> listOfTextKey = new ArrayList<>();
			GenericRequestBean genericBean = new GenericRequestBean();
			genericBean.setOperation(GSAMConstants.CONFIG_SET);

			TextKey textKey = new TextKey();
			textKey.setName(GSAMConstants.IRA_RACF_AUTH_PROFILE_TXT);
			
			listOfTextKey.add(textKey);
			genericBean.setTextKeys(listOfTextKey);
			genericBean.setUce("true");
			
			List<ExprKey> exprKeys = new ArrayList<>();
	        ExprKey exprKey = new ExprKey();
	        exprKey.setName(GSAMConstants.IS_ECS_ADMIN);
	        exprKeys.add(exprKey);
	        genericBean.setExprKeys(exprKeys); 

			responseData = widgetClient.getListOfAsset(genericBean);
		}
		catch (Exception e)
		{
			ErrorLogEventHelper.logErrorEvent("getTextValue", "Error while getTextValue Method", "getTextValue", e, ErrorLogEvent.ERROR_SEVERITY);
		}
		return responseData;
	}
	
	@SuppressWarnings("unchecked")
	private static String getUCETextValue(Map<Object, Object> configDataMap, String textName)
	{
		String text = null;
		if (Objects.nonNull(configDataMap) && configDataMap.containsKey(GSAMConstants.TEXT_UCE))
		{
			Map<Object, Object> texts = (Map<Object, Object>) configDataMap.get(GSAMConstants.TEXT_UCE);
			if (Objects.nonNull(texts) && texts.containsKey(textName))
			{
				text = (String) texts.get(textName);
			}
		}
		return text;
	}

	public static boolean getExprValue(List<Map<Object, Object>> goldDataList, String expression)
	{
		Object resultObject = getValue(goldDataList, "expr", expression);
		return resultObject == null ? Boolean.FALSE : Boolean.valueOf(resultObject.toString());
 
	}
	
	@SuppressWarnings("unchecked")
	public static Object getValue(List<Map<Object, Object>> goldDataList, String parentAttribute, String extractKey)
	{
		if (goldDataList != null && !goldDataList.isEmpty())
		{
			Map<Object, Object> linkMap = (Map<Object, Object>) goldDataList.get(0).get(parentAttribute);
			if (null != linkMap && linkMap.containsKey(extractKey))
			{
				return linkMap.get(extractKey);
			}
		}
		return null;
	}
	/**
	 * Gets Signed JWT Token.
	 * @param tokenTimeout
	 * @param brokerUserId
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getSigningKey(GSOAuthProperties oauthProps) throws Exception {
		PrivateKey privateKey = null;
		AlightKeyStore keyStore = AlightKeyStore.getInstance();

		String alias = oauthProps.getJwtSigningKeyAlias();

		try {
			privateKey = keyStore.getPrivateKey(alias, oauthProps);
		} catch (Exception e1) {
			StringBuilder msg = new StringBuilder();
			msg.append("Unable to read signing key with alias ")
				.append(alias).append(" from ")
				.append(oauthProps.getKeystoreLocation());
			throw new Exception(msg.toString(), e1);
		}
		return privateKey;
	}
	
}
