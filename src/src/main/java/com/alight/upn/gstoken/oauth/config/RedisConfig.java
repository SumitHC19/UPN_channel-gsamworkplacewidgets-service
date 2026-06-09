package com.alight.upn.gstoken.oauth.config;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.web.client.RestTemplate;

import com.alight.upn.gstoken.oauth.util.DistributedSessionCacheRedisUtil;
import com.aonhewitt.upoint.cache.config.LettuceRedisConfiguration;
import com.aonhewitt.upoint.cache.config.provider.ICache;
import com.aonhewitt.upoint.cache.util.UPNLettuceConnectionUtil;

@Configuration
@EnableConfigurationProperties({LettuceRedisConfiguration.class,RedisProperties.class})
public class RedisConfig
{
	private static final String REDIS_TEMPLATE_OBJECT = "redisTemplateforObject";
	private static final String REDIS_TEMPLATE_MAP = "redisTemplateforMap";

	@Value("${spring.data.redis.client-type:jedis}")
	private String redisClientType;

	@Value("${spring.application.name}")
	private String applicationName;
	
	@Autowired
	@Lazy		// to resolve circular dependency
	@Qualifier("redisCacheObjectProvider")
	private ICache redisCacheProvider;
	
	@Bean(name = "distributedSessionCacheRedisUtil")
	public DistributedSessionCacheRedisUtil distributedSessionCacheRedisUtil() {
		return new DistributedSessionCacheRedisUtil(redisCacheProvider);
	}

	@Autowired(required = false)
	private LettuceRedisConfiguration lettuceRedisConfiguration;

	@Autowired
	private RedisProperties redisProperties;
	
	@Bean
	public RestTemplate restTemplate() {
		return new RestTemplate();
	}

	@Primary
	@Bean(REDIS_TEMPLATE_OBJECT)
	public RedisTemplate<String, Object> redisTemplateForObject(RedisConnectionFactory redisConnectionFactory)
	{
		RedisTemplate<String, Object> template = new RedisTemplate<String, Object>();
		template.setConnectionFactory(createRedisConnectionFactory(redisConnectionFactory, lettuceRedisConfiguration, redisProperties));
		template.setKeySerializer(new StringRedisSerializer());
		return template;

	}

	@Primary
	@Bean(REDIS_TEMPLATE_MAP)
	public RedisTemplate<String, Map<Object, Object>> redisTemplateforMap(RedisConnectionFactory redisConnectionFactory)
	{
		RedisTemplate<String, Map<Object, Object>> template = new RedisTemplate<String, Map<Object, Object>>();
		template.setConnectionFactory(createRedisConnectionFactory(redisConnectionFactory, lettuceRedisConfiguration, redisProperties));
		template.setKeySerializer(new StringRedisSerializer());
		return template;
	}
	
	private RedisConnectionFactory createRedisConnectionFactory(RedisConnectionFactory redisConnectionFactory,
			LettuceRedisConfiguration lettuceRedisConfiguration, RedisProperties springDataRedisProperties) {
		if (redisClientType.isEmpty() || "jedis".equalsIgnoreCase(redisClientType)) {
			return redisConnectionFactory;
		} else {
			return UPNLettuceConnectionUtil.createPrimaryLettuceConnectionFactory(redisConnectionFactory,
					lettuceRedisConfiguration, springDataRedisProperties, applicationName);
		}
	}
}
