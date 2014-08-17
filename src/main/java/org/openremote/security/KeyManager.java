/*
 * OpenRemote, the Home of the Digital Home.
 * Copyright 2008-2014, OpenRemote Inc.
 *
 * See the contributors.txt file in the distribution for a
 * full listing of individual contributors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.openremote.security;

import org.openremote.base.exception.IncorrectImplementationException;
import org.openremote.base.exception.OpenRemoteException;
import org.openremote.logging.Logger;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Abstract superclass with a shared implementation to handle keystore based operations.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public abstract class KeyManager
{

  // Constants ------------------------------------------------------------------------------------

  /**
   * This is the default key storage type used if nothing else is specified. Note that PKCS12
   * is used for asymmetric PKI keys but not for storing symmetric secret keys. For the latter,
   * other provider-specific storage types must be used. <p>
   *
   * Default: {@value}
   */
  public final static StorageType DEFAULT_KEYSTORE_STORAGE_TYPE = StorageType.PKCS12;

  /**
   * The default security provider used by this instance. Note that can contain a null value
   * if loading of the security provider fails. A null value should indicate using the system
   * installed security providers in their preferred order rather than this explicit security
   * provider. <p>
   *
   * Default: {@value}
   */
  public final static SecurityProvider DEFAULT_SECURITY_PROVIDER = SecurityProvider.BC;


  // Enums ----------------------------------------------------------------------------------------

  /**
   * Format for storing, serializing and persisting private and secret key information. Defines
   * the known types as per the document
   * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#KeyStore
   * and BouncyCastle (release 1.50) keystore types defined in
   * http://www.bouncycastle.org/specifications.html
   */
  public enum StorageType
  {
    /**
     * PKCS #12 format. Used to store private keys of a key pair along with its X.509
     * certificate. Standardized format.
     */
    PKCS12,

    /**
     * Proprietary 'Java Keystore' format in Java cryptography extension ('SunJCE') provider.
     * This implementation uses password based encryption with Triple DES. See
     * http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#JceKeystore
     */
    JCEKS,

    /**
     * BouncyCastle keystore format roughly equivalent to Sun JKS implementation. Works with
     * Sun's 'keytool'. Resistant to tampering but not resistant to inspection.
     */
    BKS,

    /**
     * Recommended BouncyCastle keystore format. Requires password verification and is
     * resistant to inspection and tampering.
     */
    UBER;


    /**
     * Returns the name of this storage type. Standard names are defined in the  Java SE 6
     * security guide: http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     *
     * BouncyCastle storage names are defined in BouncyCastle provider documentation.
     *
     * @see #getStorageTypeName()
     *
     * @return  keystore name string
     */
    @Override public String toString()
    {
      return getStorageTypeName();
    }

    /**
     * Returns the name of this storage type. Standard names are defined in the  Java SE 6
     * security guide: http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     *
     * BouncyCastle storage names are defined in BouncyCastle provider documentation.
     *
     * @return  keystore name string
     */
    public String getStorageTypeName()
    {
      return name();
    }
  }


  // Class Members --------------------------------------------------------------------------------

  /**
   * Default logger for the security package.
   */
  protected final static Logger securityLog = Logger.getInstance(SecurityLog.DEFAULT);


  // Private Instance Fields ----------------------------------------------------------------------

  /**
   * The key storage type used by this instance.
   */
  private Storage storage = DEFAULT_KEYSTORE_STORAGE;

  /**
   * The storage type used by this instance.
   */
  private StorageType storage = DEFAULT_KEYSTORE_STORAGE_TYPE;

  /**
   * Reference to the internal keystore instance that is used to persist the key entries in
   * this key manager.
   */
  private KeyStore keystore = null;



  // Constructors ---------------------------------------------------------------------------------

  /**
   * Creates a new key manager instance with a {@link #DEFAULT_KEYSTORE_STORAGE default} key
   * storage format using {@link #DEFAULT_SECURITY_PROVIDER default} security provider.
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if creating the keystore fails
   */
  protected KeyManager() throws ConfigurationException, KeyManagerException
  {
    this(DEFAULT_KEYSTORE_STORAGE, DEFAULT_SECURITY_PROVIDER.getProviderInstance());
  }

  /**
   * This constructor allows the subclasses to specify both the key storage format and explicit
   * security provider to use with this instance. The key storage format and security provider
   * given as arguments will be used instead of the default values for this instance. <p>
   *
   * Note that the security provider parameter allows a null value. This indicates that the
   * appropriate security provider should be searched from the JVM installed security providers
   * in their preferred order.
   *
   *
   * @param storage
   *            key storage format to use with this instance
   *
   * @param provider
   *            The explicit security provider to use with the key storage of this instance. If a
   *            null value is specified, the implementations should opt to delegate the selection
   *            of a security provider to the JVMs installed security provider implementations.
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if creating the keystore fails
   */
  protected KeyManager(Storage storage, Provider provider)
      throws ConfigurationException, KeyManagerException
  {
    init(storage, provider);

    loadKeyStore((InputStream) null, null);
  }


  /**
   * This constructor will load an existing keystore into memory. It expects the keystore
   * to be in default key storage format as specified in {@link #DEFAULT_KEYSTORE_STORAGE}. <p>
   *
   * The URI to a keystore file must use a 'file' scheme.
   *
   *
   * @param keyStoreFile
   *            a file URI pointing to a keystore file that should be loaded into this key
   *            manager
   *
   * @param password
   *            a master password to access the keystore file
   *
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if creating the keystore fails
   */
  protected KeyManager(URI keyStoreFile, char[] password) throws ConfigurationException,
                                                                 KeyManagerException
  {
    this(
        keyStoreFile, password,
        DEFAULT_KEYSTORE_STORAGE,
        DEFAULT_SECURITY_PROVIDER.getProviderInstance()
    );
  }


  /**
   * This constructor will load an existing keystore into memory. It allows the subclasses to
   * specify the expected key storage format used by the keystore file. The storage format
   * must be supported by the {@link #DEFAULT_SECURITY_PROVIDER} implementation. <p>
   *
   * The URI to a keystore file must use a 'file' scheme.
   *
   *
   * @param keyStoreFile
   *            a file URI pointing to a keystore file that should be loaded into this key
   *            manager
   *
   * @param password
   *            a master password to access the keystore file
   *
   * @param storage
   *            key storage format to use with this instance
   *
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if creating the keystore fails
   */
  protected KeyManager(URI keyStoreFile, char[] password, Storage storage)
      throws ConfigurationException, KeyManagerException
  {
    this(keyStoreFile, password, storage, DEFAULT_SECURITY_PROVIDER.getProviderInstance());
  }

  /**
   * This constructor will load an existing keystore into memory. It allows the subclasses to
   * specify both the expected key storage format and explicit security provider to be used
   * when the keystore is loaded. <p>
   *
   * Note that the security provider parameter allows a null value. This indicates that the
   * appropriate security provider should be searched from the JVM installed security providers
   * in their preferred order.  <p>
   *
   * The URI to a keystore file must use a 'file' scheme.
   *
   *
   * @param keyStoreFile
   *            a file URI pointing to a keystore file that should be loaded into this key
   *            manager
   *
   * @param password
   *            a master password to access the keystore file
   *
   * @param storage
   *            key storage format to use with this instance
   *
   * @param provider
   *            The explicit security provider to use with the key storage of this instance. If a
   *            null value is specified, the implementations should opt to delegate the selection
   *            of a security provider to the JVMs installed security provider implementations.
   *
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if creating the keystore fails
   */
  protected KeyManager(URI keyStoreFile, char[] password, Storage storage, Provider provider)
      throws ConfigurationException, KeyManagerException
  {
    this(storage, provider);

    load(keyStoreFile, password);
  }


  // Public Instance Methods ----------------------------------------------------------------------

  /**
   * Indicates if this key manager contains a key with a given alias.
   *
   * @param keyAlias
   *          key alias to check
   *
   * @return  true if a key is associated with a given alias in this key manager; false
   *          otherwise
   */
  public boolean contains(String keyAlias)
  {
    try
    {
      return keystore.containsAlias(keyAlias);
    }

    catch (KeyStoreException exception)
    {
      securityLog.error(
          "Unable to retrieve key info for alias '{0}' : {1}", exception,
          keyAlias, exception.getMessage()
      );

      return false;
    }
  }


  /**
   * Returns the number of keys currently managed in this key manager.
   *
   * @return  number of keys in this key manager
   */
  public int size()
  {
    try
    {
      return keystore.size();
    }

    catch (KeyStoreException exception)
    {
     securityLog.error(
         "Unable to retrieve keystore size : {0}", exception,
         exception.getMessage()
     );

      return -1;
    }
  }


  // Protected Instance Methods -------------------------------------------------------------------

  /**
   * Initialization method used by constructors to initialize this instance. Should not be
   * invoked outside of a constructor.  <p>
   *
   * @param storage
   *            The keystore storage type to use with this instance.
   *
   * @param provider
   *            The security provider to use with this instance. Can be null in which case
   *            the implementations should delegate to the JVM installed security providers
   *            in their preferred use order.
   */
  protected void init(Storage storage, Provider provider)
  {
    if (storage == null)
    {
      throw new IllegalArgumentException("Implementation Error: null storage type");
    }

    this.provider = provider;
    this.storage = storage;
  }


  /**
   * Stores the keys in this key manager in a secure key store format. This implementation generates
   * a file-based, persistent key store which can be shared with other applications and processes.
   * <p>
   * IMPORTANT NOTE: Subclasses that invoke this method should clear the password character array
   *                 as soon as it is no longer needed. This prevents passwords from lingering
   *                 in JVM memory pool any longer than is necessary. Use the
   *                 {@link #clearPassword(char[])} method for this purpose.
   *
   * @param uri
   *              The location of the file where the key store should be persisted. Must be
   *              an URI with file scheme.
   *
   * @param password
   *              A secret password used to access the keystore contents. NOTE: the character
   *              array should be set to zero values after this method call completes, via
   *              {@link #clearPassword(char[])} method.
   *
   * @see #clearPassword(char[])
   *
   * @throws KeyManagerException
   *              if loading or creating the keystore fails
   */
  protected void save(URI uri, char[] password) throws ConfigurationException,
                                                       KeyManagerException
  {
    if (uri == null)
    {
      throw new KeyManagerException("Save failed due to null URI.");
    }

    try
    {
      BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(new File(uri)));

      // Persist...

      save(keystore, out, password);
    }

    catch (FileNotFoundException exception)
    {
      throw new KeyManagerException(
          "File ''{0}'' cannot be created or opened : {1}", exception,
          resolveFilePath(new File(uri)), exception.getMessage()
      );
    }

    catch (SecurityException exception)
    {
      throw new KeyManagerException(
          "Security manager has denied access to file ''{0}'' : {1}", exception,
          resolveFilePath(new File(uri)), exception.getMessage()
      );
    }
  }


  /**
   * Loads existing, persisted key store contents into this instance. Any previous keys in this
   * key manager instance are overridden. <p>
   *
   * IMPORTANT NOTE: Subclasses that invoke this method should clear the password character array
   *                 as soon as it is no longer needed. This prevents passwords from lingering
   *                 in JVM memory pool any longer than is necessary. Use the
   *                 {@link #clearPassword(char[])} method for this purpose.
   *
   * @param uri
   *              URI with file scheme pointing to the file system location of the keystore
   *              to load
   *
   * @param keystorePassword
   *              The password to access the keystore. Note that the subclasses invoking this
   *              method are responsible for resetting the password character array after use.
   *
   * @see #clearPassword(char[])
   *
   * @throws ConfigurationException
   *              if the configured security provider(s) do not contain implementation for the
   *              required keystore type
   *
   * @throws KeyManagerException
   *              if loading the keystore fails
   */
  protected void load(URI uri, char[] keystorePassword) throws KeyManagerException
  {
    if (uri == null)
    {
      throw new KeyManagerException("Implementation Error: null file URI.");
    }

    loadKeyStore(new File(uri), keystorePassword);
  }


  /**
   * Adds a key entry to this instance. Use {@link #save(URI, char[])} to persist
   * if desired.
   *
   * @param keyAlias
   *            A lookup name of the key entry to be added.
   *
   * @param entry
   *            Key entry to be added. Note that accepted entry types depend on the
   *            keystore storage format.
   *
   * @param param
   *            Protection parameters for the key entry.  A null value is accepted for
   *            trusted certificate entries, for other type of key entries a null value
   *            is converted to an empty password character array.
   */
  protected void add(String keyAlias, KeyStore.Entry entry, KeyStore.ProtectionParameter param)
      throws KeyManagerException
  {
    if (keyAlias == null || keyAlias.equals(""))
    {
      throw new KeyManagerException(
          "Implementation Error: null or empty key alias is not allowed."
      );
    }

    if (entry == null)
    {
      throw new KeyManagerException(
          "Implementation Error: null keystore entry is not allowed."
      );
    }

    // Key stores appear to behave differently with regards to key entries depending what
    // types of entries are stored (and possibly differing between store implementations too).
    // E.g. private keys may have a strict requirement for a key protection where public
    // certificates may not allow protection parameters at all.
    //
    // Doing some special handling here depending what type of entry is being stored:
    //
    //   - if a null protection parameter is provided, it is converted to an empty password
    //     protection unless the null protection parameter is for a trusted certificate
    //     entry in which case it is accepted.

    if (param == null)
    {
      param = new KeyStore.PasswordProtection(new char[] {});
    }

    if (entry instanceof KeyStore.TrustedCertificateEntry)
    {
      param = null;
    }

    try
    {
      keystore.setEntry(keyAlias, entry, param);
    }

    catch (KeyStoreException exception)
    {
      throw new KeyManagerException(
          "Failed to add key '{0}' to key store : {1}", exception,
          keyAlias, exception.getMessage());
    }
  }


  /**
   * Removes a key entry from this instance. Use {@link #save(URI, char[])} to persist
   * if desired.
   *
   * @param keyAlias
   *            A lookup name of the key entry to be removed.
   *
   * @return    true if key was removed, false otherwise
   */
  protected boolean remove(String keyAlias)
  {
    try
    {
      keystore.deleteEntry(keyAlias);

      return true;
    }

    catch (KeyStoreException exception)
    {
      securityLog.error(
          "Unable to remove key alias '{0}' : {1}", exception,
          keyAlias, exception.getMessage()
      );

      return false;
    }
  }


  /**
   * Retrieves a key from underlying key storage.
   *
   * @param alias
   *          Key alias of the key to retrieve.
   *
   * @param protection
   *          Protection parameter to retrieve the key.
   *
   * @return  a key store entry, or null if it was not found
   *
   * @throws KeyManagerException
   *          if the key could not be retrieved, due to incorrect protection parameters,
   *          unsupported algorithm or other reasons
   */
  protected KeyStore.Entry retrieveKey(String alias, KeyStore.ProtectionParameter protection)
      throws KeyManagerException
  {
    try
    {
      return keystore.getEntry(alias, protection);
    }

    catch (KeyStoreException exception)
    {
      throw new IncorrectImplementationException(
          "Implementation Error: password manager has not been initialized.", exception
      );
    }

    catch (NoSuchAlgorithmException exception)
    {
      throw new KeyManagerException(
          "Configuration error. Required key storage algorithm is not available: {0}", exception,
          exception.getMessage()
      );
    }

    catch (UnrecoverableKeyException exception)
    {
      throw new KeyManagerException(
          "Password with alias ''{0}'' could not be retrieved, possibly due to incorrect " +
          "protection password: {1}", exception,
          alias, exception.getMessage()
      );
    }

    catch (UnrecoverableEntryException exception)
    {
      throw new KeyManagerException(
          "Password with alias ''{0}'' could not be retrieved, possibly due to incorrect " +
          "protection password: {1}", exception,
          alias, exception.getMessage()
      );
    }
  }


  /**
   * Checks if keystore exists at given file URI.
   *
   * @param uri
   *            the file URI to check
   *
   * @return    true if file exists, false otherwise
   *
   * @throws KeyManagerException
   *            if security manager has denied access to file information
   */
  protected boolean exists(URI uri) throws KeyManagerException
  {
    File file = new File(uri);

    try
    {
      return file.exists();
    }

    catch (SecurityException e)
    {
      String path = resolveFilePath(file);

      throw new KeyManagerException(
          "Security manager has prevented access to file ''{0}'' : {1}",
          e, path, e.getMessage()
      );
    }
  }


  /**
   * Initialization method used by constructors to initialize this instance. Should not be
   * invoked outside of a constructor.
   *
   * @param storage
   *            The keystore storage type to use with this instance.
   *
   * @param provider
   *            The security provider to use with this instance. Can be null in which case
   *            the implementations should delegate to the JVM installed security providers
   *            in their preferred use order.
   */
  protected void init(StorageType storage, Provider provider)
  {
    if (storage == null)
    {
      throw new IllegalArgumentException("Implementation Error: null storage type");
    }

    this.provider = provider;
    this.storage = storage;
  }


  // Private Instance Methods ---------------------------------------------------------------------

  /**
   * Adds the key entries of this key manager into a keystore. The keystore is saved to the given
   * output stream. The keystore can be an existing, loaded keystore or a new, empty one.
   *
   * @param keystore
   *            keystore to add keys from this key manager to
   *
   * @param out
   *            the output stream for the keystore (can be used for persisting the keystore to disk)
   *
   * @param password
   *            password to access the keystore
   *
   * @return    an in-memory keystore instance
   *
   * @throws KeyManagerException
   *            if the save operation fails
   */
  private KeyStore save(KeyStore keystore, OutputStream out, char[] password)
      throws KeyManagerException
  {
    if (password == null || password.length == 0)
    {
      throw new KeyManagerException(
          "Null or empty password. Keystore must be protected with a password."
      );
    }

    BufferedOutputStream bout = new BufferedOutputStream(out);

    try
    {
      for (String keyAlias : keyEntries.keySet())
      {
        KeyStoreEntry entry = keyEntries.get(keyAlias);

        keystore.setEntry(keyAlias, entry.entry, entry.protectionParameter);
      }

      keystore.store(bout, password);

      return keystore;
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException("Storing the key pair failed : {0}", e, e.getMessage());
    }

    catch (IOException e)
    {
      throw new KeyManagerException(
          "Unable to write key to keystore : {0}", e, e.getMessage()
      );
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new KeyManagerException(
          "Security provider does not support required key store algorithm: {0}", e, e.getMessage()
      );
    }

    catch (CertificateException e)
    {
      throw new KeyManagerException("Cannot store certificate: {0}", e, e.getMessage());
    }

    finally
    {
      if (bout != null)
      {
        try
        {
          bout.flush();
          bout.close();
        }

        catch (IOException e)
        {
          securityLog.warn("Failed to close file output stream to keystore : {0}", e, e.getMessage());
        }
      }
    }
  }


  /**
   * Loads a keystore instance from an existing file URI.
   *
   * @param uri
   *            file URI to load the keystore from
   *
   * @param password
   *            password to access the keystore
   *
   * @return    in-memory keystore instance
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if loading or creating the keystore fails
   */
  private KeyStore instantiateKeyStore(URI uri, char[] password)
      throws ConfigurationException, KeyManagerException
  {
    return instantiateKeyStore(new File(uri), password, storage);
  }

  /**
   * Loads a keystore instance from an existing file.
   *
   * @param file
   *            file to load the keystore from
   *
   * @param password
   *            password to access the keystore
   *
   * @param type
   *            the algorithm used to store the keystore data
   *
   * @return    in-memory keystore instance
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if loading or creating the keystore fails
   */
  private KeyStore instantiateKeyStore(File file, char[] password, StorageType type)
      throws ConfigurationException, KeyManagerException
  {
    if (file == null)
    {
      throw new KeyManagerException("Implementation Error: null file descriptor.");
    }

    try
    {
      BufferedInputStream in = new BufferedInputStream(new FileInputStream(file));

      return getKeyStore(in, password, type);
    }

    catch (FileNotFoundException e)
    {
      throw new KeyManagerException(
          "Keystore file ''{0}'' could not be created or opened : {1}",
          e, resolveFilePath(file), e.getMessage()
      );
    }

    catch (SecurityException e)
    {
      throw new KeyManagerException(
          "Security manager has denied access to keystore file ''{0}'' : {1}",
          e, resolveFilePath(file), e.getMessage()
      );
    }
  }


  /**
   * Loads a key store from input stream (or creates a new, empty one). The keystore storage
   * format can be provided as a parameter.
   *
   * @param in
   *            input stream to keystore file (or null to create a new one)
   *
   * @param password
   *            shared secret (a password) used for protecting access to the keystore
   *
   * @param type
   *            the algorithm used to securely store the keystore data
   *
   * @return  an in-memory keystore instance
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if loading or creating the keystore fails
   */
  private KeyStore getKeyStore(InputStream in, char[] password, StorageType type)
      throws ConfigurationException, KeyManagerException
  {
    try
    {
      KeyStore keystore;

      if (provider == null)
      {
        keystore = KeyStore.getInstance(type.name());
      }

      else
      {
        keystore = KeyStore.getInstance(type.name(), provider);
      }

      keystore.load(in, password);

      return keystore;
    }

    catch (KeyStoreException e)
    {
      // NOTE:  If the algorithm is not recognized by a provider, it is indicated by a nested
      //        NoSuchAlgorithmException. This is the behavior for both SUN default provider
      //        in Java 6 and BouncyCastle.

      if (e.getCause() != null && e.getCause() instanceof NoSuchAlgorithmException)
      {
        String usedProviders;

        if (provider == null)
        {
          usedProviders = Arrays.toString(Security.getProviders());
        }

        else
        {
          usedProviders = provider.getName();
        }

        throw new ConfigurationException(
            "The security provider(s) ''{0}'' do not support keystore type ''{1}'' : {2}",
            e, usedProviders, type.name(), e.getMessage()
        );
      }

      throw new KeyManagerException("Cannot load keystore: {0}", e, e.getMessage());
    }

    catch (NoSuchAlgorithmException e)
    {
      // If part of the keystore load() the algorithm to verify the keystore contents cannot
      // be found...

      throw new KeyManagerException(
          "Required keystore verification algorithm not found: {0}",
          e, e.getMessage()
      );
    }

    catch (CertificateException e)
    {
      // Can happen if any of the certificates in the store cannot be loaded...

      throw new KeyManagerException("Can't load keystore: {0}", e, e.getMessage());
    }

    catch (IOException e)
    {
      // If there's an I/O problem, or if keystore has been corrupted, or if password is missing

//      if (e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException)
//      {
//        // The Java 6 javadoc claims that an incorrect password can be detected by having
//        // a nested UnrecoverableKeyException in the wrapping IOException -- this doesn't
//        // seem to be the case or is not working... incorrect password is reported as an
//        // IOException just like other I/O errors with no root causes as far as I'm able to
//        // tell. So leaving this out for now
//        //                                                                        [JPL]
//        //
//        throw new PasswordException(
//            "Cannot recover keys from keystore (was the provided password correct?) : {0}",
//            e.getMessage(), e
//        );
//      }

      throw new KeyManagerException("Cannot load keystore: {0}", e, e.getMessage());
    }
  }


  /**
   * File utility to print file path.
   *
   * @param file
   *              file path to print
   *
   * @return      resolves to an absolute file path if allowed by the security manager, if not
   *              returns the file path as defined in the file object parameter
   */
  private String resolveFilePath(File file)
  {
    try
    {
      return file.getAbsolutePath();
    }

    catch (SecurityException e)
    {
      return file.getPath();
    }
  }



  // Nested Classes -------------------------------------------------------------------------------

  /**
   * Convenience class to hold keystore entry and its protection parameter as single entity in
   * collections.
   */
  private static class KeyStoreEntry
  {
    private KeyStore.Entry entry;
    private KeyStore.ProtectionParameter protectionParameter;

    private KeyStoreEntry(KeyStore.Entry entry, KeyStore.ProtectionParameter param)
    {
      this.entry = entry;
      this.protectionParameter = param;
    }
  }


  /**
   * Exception type for the public API of this class to indicate errors.
   */
  public static class KeyManagerException extends OpenRemoteException
  {
    protected KeyManagerException(String msg)
    {
      super(msg);
    }

    protected KeyManagerException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }

  /**
   * Specific subclass of KeyManagerException that indicates a security configuration issue.
   */
  public static class ConfigurationException extends KeyManagerException
  {
    protected ConfigurationException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }

}

