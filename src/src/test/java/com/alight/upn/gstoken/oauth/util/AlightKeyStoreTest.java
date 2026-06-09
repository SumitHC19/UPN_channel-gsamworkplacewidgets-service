package com.alight.upn.gstoken.oauth.util;

import com.alight.upn.gstoken.oauth.config.GSOAuthProperties;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
public class AlightKeyStoreTest {
	
	 private AlightKeyStore keyStoreInstance;
	    private GSOAuthProperties mockProps;

	    @BeforeEach
	    void setUp() throws Exception {
	        keyStoreInstance = AlightKeyStore.getInstance();
	        mockProps = mock(GSOAuthProperties.class);
	        resetSingletonState();
	    }
	    
	  
	    void resetSingletonState() throws Exception {
	        Field fileField = AlightKeyStore.class.getDeclaredField("keyStoreFile");
	        fileField.setAccessible(true);
	        fileField.set(AlightKeyStore.getInstance(), null);

	        Field keyStoreField = AlightKeyStore.class.getDeclaredField("keyStore");
	        keyStoreField.setAccessible(true);
	        keyStoreField.set(AlightKeyStore.getInstance(), null);

	        Field lastModifiedField = AlightKeyStore.class.getDeclaredField("lastModified");
	        lastModifiedField.setAccessible(true);
	        lastModifiedField.set(AlightKeyStore.getInstance(), 0L);
	    }

	    @Test
	    void testSingletonInstance() {
	        AlightKeyStore instance1 = AlightKeyStore.getInstance();
	        AlightKeyStore instance2 = AlightKeyStore.getInstance();
	        assertSame(instance1, instance2, "Should return the same singleton instance");
	    }

	    @Test
	    void testGetKeyStoreFileExists() throws Exception {
	        File tempFile = File.createTempFile("keystore", ".jks");
	        when(mockProps.getKeystoreLocation()).thenReturn(tempFile.getAbsolutePath());

	        File result = keyStoreInstance.getKeyStoreFile(mockProps);
	        assertNotNull(result);
	        assertTrue(result.exists());
	    }

	    @Test
	    void testGetKeyStoreFileNotExists() throws Exception {
	        when(mockProps.getKeystoreLocation()).thenReturn("nonexistent.jks");

	        File result = keyStoreInstance.getKeyStoreFile(mockProps);
	        assertNull(result, "Should return null if file doesn't exist");
	    }

	    @Test
	    void testLoadKeyStoreSuccess() throws Exception {
	        File tempFile = File.createTempFile("keystore", ".jks");

	        // Create a dummy keystore
	        KeyStore ks = KeyStore.getInstance("JKS");
	        ks.load(null, "password".toCharArray());
	        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
	            ks.store(fos, "password".toCharArray());
	        }

	        try (MockedStatic<GSOAuthUtil> mockedUtil = Mockito.mockStatic(GSOAuthUtil.class)) {
	            mockedUtil.when(() -> GSOAuthUtil.getSecret(anyString(), anyString()))
	                      .thenReturn("password");

	            KeyStore loaded = keyStoreInstance.loadKeyStore(tempFile, "dev");
	            assertNotNull(loaded);
	        }
	    }

	    @Test
	    void testLoadKeyStoreFailure() {
	        File invalidFile = new File("invalid.jks");

	        try (MockedStatic<GSOAuthUtil> mockedUtil = Mockito.mockStatic(GSOAuthUtil.class)) {
	            mockedUtil.when(() -> GSOAuthUtil.getSecret(anyString(), anyString()))
	                      .thenReturn("password");

	            Exception ex = assertThrows(Exception.class, () ->
	                keyStoreInstance.loadKeyStore(invalidFile, "dev")
	            );
	            assertTrue(ex.getMessage().contains("Invalid keystore"));
	        }
	    }

	    @Test
	    void testGetPrivateKeyThrowsException() throws Exception {
	        File tempFile = File.createTempFile("keystore", ".jks");

	        KeyStore ks = KeyStore.getInstance("JKS");
	        ks.load(null, "password".toCharArray());
	        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
	            ks.store(fos, "password".toCharArray());
	        }

	        when(mockProps.getKeystoreLocation()).thenReturn(tempFile.getAbsolutePath());
	        when(mockProps.getLifecycle()).thenReturn("dev");

	        try (MockedStatic<GSOAuthUtil> mockedUtil = Mockito.mockStatic(GSOAuthUtil.class)) {
	            mockedUtil.when(() -> GSOAuthUtil.getSecret(anyString(), anyString()))
	                      .thenReturn("wrongpassword");

	            Exception ex = assertThrows(Exception.class, () ->
	                keyStoreInstance.getPrivateKey("alias", mockProps)
	            );
	            assertFalse(ex.getMessage().contains("Unable to read JWT key"));
	        }
	    }

	    @Test
	    void testGetKeyStoreThrowsIfNull() {
	        assertThrows(Exception.class, () -> {
	            keyStoreInstance.getKeyStore(mockProps);
	        });
	    }

}
