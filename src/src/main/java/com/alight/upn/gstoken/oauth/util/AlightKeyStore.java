package com.alight.upn.gstoken.oauth.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import com.alight.logging.helpers.InfoTypeLogEventHelper;
import com.alight.upn.gstoken.oauth.config.GSOAuthProperties;

public class AlightKeyStore {

	private static volatile AlightKeyStore cInstance;
	private File keyStoreFile;
	private KeyStore keyStore;
	private long lastModified;
	private static final String CLASS_NAME = AlightKeyStore.class.getName();
	
	/**
	 * Creates a new AlightKeyStore.
	 * 
	 * @param oauthProps service configuration properties.
	 */
	private AlightKeyStore() {
	}
	
	/**
	 * Creates a singleton instance of the AlightKeyStore.
	 * 
	 * @param oauthProps service configuration properties.
	 * @return the AlightKeystore.
	 */
	public static AlightKeyStore getInstance() {
		/*if (cInstance == null ) {
			cInstance = new AlightKeyStore();
		}*/
		if (cInstance == null) {
            synchronized (AlightKeyStore.class) {
                if (cInstance == null) {
                    cInstance = new AlightKeyStore();
                }
            }
		}
		return cInstance;
	}

	/**
	 * Retrieves a private key from the keystore.
	 * 
	 * @param alias the key alias.
	 * @return the private key for the specified alias.
	 * @throws Exception if the keystore cannot be accessed.
	 */
	public PrivateKey getPrivateKey(String alias, GSOAuthProperties oauthProps) throws Exception {
		PrivateKey key = null;
		KeyStore keyStore = getKeyStore(oauthProps);
		try {
			String password = GSOAuthUtil.getSecret("ALIGHT_KEYSTORE_PASSWORD", oauthProps.getLifecycle());
			key = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
			throw new Exception("Unable to read JWT key from keystore");
		}
		return key;

	}

	/**
	 * Retrieves and loads the keystore.
	 * @param isCustom TODO
	 * 
	 * @return the keystore.
	 * @throws Exception if the keystore cannot be accessed.
	 */
	public KeyStore getKeyStore(GSOAuthProperties oauthProps) throws Exception {
		File keyStoreFile = getKeyStoreFile(oauthProps);
		if (keyStoreFile != null && keyStoreFile.lastModified() != lastModified) {
			KeyStore tempKeyStore = loadKeyStore(keyStoreFile, oauthProps.getLifecycle());
			long prevLastModified = lastModified;
			lastModified = keyStoreFile.lastModified();
			keyStore = tempKeyStore;
			InfoTypeLogEventHelper.logInfoEvent(this.getClass().getName(), 
                                      "Alight Keystore File has been modified at : " + lastModified + "    Previous modification time : " + prevLastModified);
		}
		if (keyStore == null) {
			throw new Exception("Unable to load keystore for JWT");
		}
		return keyStore;
	}
	
	/**
	 * Locates the keystore file.
	 * 
	 * @return the keystore file.
	 * @throws Exception if the keystore file cannot be located.
	 */
	public File getKeyStoreFile(GSOAuthProperties oauthProps) throws Exception {
		if (keyStoreFile == null || ! keyStoreFile.exists()) {
			String keyStoreLocation = oauthProps.getKeystoreLocation();
			File tempFile = new File(keyStoreLocation);
			if (tempFile.exists()) {
				keyStoreFile = tempFile;
			}
		}
		return keyStoreFile;
	}
	
	/**
	 * Loads the keystore from the specified file.
	 * 
	 * @param keyStoreFile the file to load into the keystore.
	 * @param isCustom TODO
	 * @return the keystore.
	 * @throws Exception if the keystore cannot be accessed.
	 */
	public KeyStore loadKeyStore(File keyStoreFile, String lifecycle) throws Exception
	{
		InfoTypeLogEventHelper.logInfoEvent(CLASS_NAME, "Inside loadKeyStore method 152");
		KeyStore tempKeyStore = null;
		InputStream is = null;
		try
		{
			String password = GSOAuthUtil.getSecret("ALIGHT_KEYSTORE_PASSWORD", lifecycle);
			InfoTypeLogEventHelper.logInfoEvent(CLASS_NAME, "Inside loadKeyStore password 158 "+password);
			tempKeyStore = KeyStore.getInstance("JKS");
			is = new FileInputStream(keyStoreFile);
			tempKeyStore.load(is, password.toCharArray());
		}
		catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e)
		{
			throw new Exception("Invalid keystore for JWT", e);
		}
		finally
		{
			if (is != null)
			{
				try
				{
					is.close();
				}
				catch (IOException e)
				{
					// Swallow it
				}
			}
		}
		return tempKeyStore;
	}
}
