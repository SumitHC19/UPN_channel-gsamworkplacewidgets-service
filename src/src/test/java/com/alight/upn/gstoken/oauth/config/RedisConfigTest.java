package com.alight.upn.gstoken.oauth.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;


import com.alight.upn.gstoken.oauth.util.DistributedSessionCacheRedisUtil;

@ExtendWith(SpringExtension.class)
public class RedisConfigTest {

	@InjectMocks
	private RedisConfig redisConfig;
	
	@Mock RedisConnectionFactory redisConnectionFactory;
	
	@BeforeEach
	public void setup() {
		MockitoAnnotations.openMocks(this);
	}
	
	 @AfterEach
	public void destruct(){
		Mockito.clearAllCaches();
	}
	 
	@Test
    public void testDistributedSessionCacheRedisUtilBeanCreation() {
        DistributedSessionCacheRedisUtil util = redisConfig.distributedSessionCacheRedisUtil();
        assertNotNull(util, "DistributedSessionCacheRedisUtil bean should not be null");
    }
	 
	@Test
    public void testRestTemplateBeanCreation() {
        RestTemplate restTemplate = redisConfig.restTemplate();
        assertNotNull(restTemplate, "RestTemplate bean should not be null");
        assertTrue(restTemplate instanceof RestTemplate, "Bean should be an instance of RestTemplate");
    }
	

	@Test
	public void redisTemplateForObject_test() {

//		redisConfig.redisTemplateForObject(new JedisConnectionFactory());
		ReflectionTestUtils.setField(redisConfig, "redisClientType", "jedis");
		redisConfig.redisTemplateForObject(redisConnectionFactory);
		ReflectionTestUtils.setField(redisConfig, "redisClientType", "lettuce");
		redisConfig.redisTemplateForObject(redisConnectionFactory);
	}

	@Test
	public void redisTemplateForMap_test() {

//		redisConfig.redisTemplateforMap(new JedisConnectionFactory());
		ReflectionTestUtils.setField(redisConfig, "redisClientType", "jedis");
		redisConfig.redisTemplateforMap(redisConnectionFactory);
		ReflectionTestUtils.setField(redisConfig, "redisClientType", "lettuce");
		redisConfig.redisTemplateforMap(redisConnectionFactory);
	}

}
