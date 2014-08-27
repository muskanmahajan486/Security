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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

/**
 * This is an abstract base class for managing and storing key material. It is useful for
 * both generating keys (and associated certificates if desired) as well as optionally
 * persisting keys and key certificates on filesystem using secure keystores.  <p>
 *
 * This abstract implementation contains several operations that the subclasses may or may not
 * choose to expose as part of their public API. If a subclass wants to expose a method
 * implementation as part of public API, it should create a public method that invokes one of
 * the protected methods in this class. Some of the method implementations in this class may
 * be unnecessarily generic to expose in API as-is, and therefore it may make sense to create
 * a more use-case specific method signatures in each subclass. For examples of protected
 * methods, see {@link #save(java.net.URI, char[])}, {@link #load(java.net.URI, char[])},
 * {@link #add(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)},
 * {@link #remove(String)}. <p>
 *
 * For examples of subclasses that may expose parts of this class protected API, see
 * {@link PasswordManager}, {@link PrivateKeyManager} classes.
 *
 * @see #save(java.net.URI, char[])
 * @see #load(java.net.URI, char[])
 * @see #add(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)
 * @see #remove(String)
 * @see PasswordManager
 * @see PrivateKeyManager
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public abstract class KeyManager
{

  // Constants ------------------------------------------------------------------------------------

  /**
   * This is the default key storage type used if nothing else is specified. <p>
   *
   * Note that the default storage format PKCS12 can only be used as an asymmetric public and
   * private key and a key certificate storage but not for other (symmetric) keys. For the latter,
   * other provider-specific storage types must be used. <p>
   *
   * Default: {@value}
   */
  public final static Storage DEFAULT_KEYSTORE_STORAGE = Storage.PKCS12;

  /**
   * The default security provider used by this instance. Note that can contain a null value
   * if loading of the security provider fails. A null value should indicate using the system
   * installed security providers in their preferred order rather than this explicit security
   * provider. <p>
   *
   * Default: {@value}
   */
  public final static SecurityProvider DEFAULT_SECURITY_PROVIDER = SecurityProvider.BC;


  /**
   * If no key-specific password is set for stored keys, use this default empty password instead.
   * Note, most keystore implementations don't allow passing a null password protection parameters
   * for keys, and some (e.g. BouncyCastle UBER) do not allow empty passwords (empty char arrays)
   * either.
   */
  public static final char[] EMPTY_KEY_PASSWORD = new char[] { '0' };


  /**
   * ASN.1 OID for NSA / NIST standard curve P-521. This is equivalent to SEC 2 prime curve
   * "secp521r1". OID = {@value}
   */
  public final static String ASN_OID_STD_CURVE_NSA_NIST_P521 = "1.3.132.0.35";

  /**
   * ASN.1 OID for NSA / NIST standard curve P-384. This is equivalent to SEC 2 prime curve
   * "secp384r1". OID = {@value}
   */
  public final static String ASN_OID_STD_CURVE_NSA_NIST_P384 = "1.3.132.0.34";

  /**
   * ASN.1 OID for NSA / NIST standard curve P-256. This is equivalent to SEC 2 prime curve
   * "secp256r1" and ANSI X9.62 "prime256v1". OID = {@value}
   */
  public final static String ASN_OID_STD_CURVE_NSA_NIST_P256 = "1.2.840.10045.3.1.7";


  /**
   * RSA key size : {@value} <p>
   *
   * This is recommended asymmetric RSA key size for classified, secret data, as per NSA Suite B.
   */
  public final static int DEFAULT_RSA_KEY_SIZE = 3072;

  /**
   * Public exponent value used in RSA algorithm (increase impacts performance): {@value}
   *
   * @see java.security.spec.RSAKeyGenParameterSpec#F4
   */
  public final static BigInteger DEFAULT_RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;



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
   * The security provider used by this instance. <p>
   *
   * Note that may contain a null reference in which case implementation should delegate to the
   * JVM installed security providers in their preferred use order.
   */
  private Provider provider = DEFAULT_SECURITY_PROVIDER.getProviderInstance();

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
      param = new KeyStore.PasswordProtection(EMPTY_KEY_PASSWORD);
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
   * A convenience method to retrieve a certificate (rather than a private or secret key)
   * from the underlying keystore.
   *
   * @param alias
   *          Certificate alias to retrieve.
   *
   * @return  A certificate, or null if not found
   */
  protected Certificate getCertificate(String alias)
  {
    try
    {
      return keystore.getCertificate(alias);
    }

    catch (KeyStoreException exception)
    {
      // This exception may happen if keystore is not initialized/loaded when asking for
      // a certificate -- since we initialize the keystore instance as part of the constructor
      // it should always be present. Therefore this exception should only occur in case of
      // an implementation error.

      throw new IncorrectImplementationException(
          "Could not retrieve certificate '{0}': {1}", exception,
          alias, exception.getMessage()
      );
    }
  }


  /**
   * Generates a new asymmetric key pair using the given algorithm.
   *
   * @param keyAlgo
   *            algorithm for the key generator
   *
   * @return generated key pair
   *
   * @throws KeyManagerException
   *            in case any errors in key generation
   */
  protected KeyPair generateKey(AsymmetricKeyAlgorithm keyAlgo) throws KeyManagerException
  {
    try
    {
      KeyPairGenerator keyGen;

      if (provider == null)
      {
        keyGen = KeyPairGenerator.getInstance(keyAlgo.getAlgorithmName());
      }

      else
      {
        keyGen = KeyPairGenerator.getInstance(keyAlgo.getAlgorithmName(), provider);
      }

      keyGen.initialize(keyAlgo.algorithmSpec);

      return keyGen.generateKeyPair();
    }

    catch (InvalidAlgorithmParameterException exception)
    {
      throw new KeyManagerException(
          "Invalid algorithm parameter in {0} : {1}", exception,
          keyAlgo, exception.getMessage()
      );
    }

    catch (NoSuchAlgorithmException exception)
    {
      throw new KeyManagerException(
          "No security provider found for {0} : {1}", exception,
          keyAlgo, exception.getMessage()
      );
    }
  }


  /**
   * Returns the key storage type used by this key manager.
   *
   * @return    key storage type
   */
  protected Storage getStorageType()
  {
    return storage;
  }


  /**
   * Checks if key store exists at given file URI.
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

    catch (SecurityException exception)
    {
      String path = resolveFilePath(file);

      throw new KeyManagerException(
          "Security manager has prevented access to file ''{0}'' : {1}", exception,
          path, exception.getMessage()
      );
    }
  }



  /**
   * Clears the given password character array with zero values.
   *
   * @param password
   *            password character array to erase
   */
  protected void clearPassword(char[] password)
  {
    if (password != null)
    {
      for (int i = 0; i < password.length; ++i)
      {
        password[i] = 0;
      }
    }
  }

  /**
   * Clears the given password byte array with zero values.
   *
   * @param password
   *            password byte array to erase
   */
  protected void clearPassword(byte[] password)
  {
    if (password != null)
    {
      for (int i = 0; i< password.length; ++i)
      {
        password[i] = 0;
      }
    }
  }


  // Private Instance Methods ---------------------------------------------------------------------


  /**
   * Stores the key entries of this key manager into a keystore. The keystore is saved to the given
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
   * @throws KeyManagerException
   *            if the save operation fails
   */
  private void save(KeyStore keystore, OutputStream out, char[] password)
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
      keystore.store(bout, password);
    }

    catch (KeyStoreException exception)
    {
      throw new KeyManagerException(
          "Storing the key pair failed : {0}", exception,
          exception.getMessage()
      );
    }

    catch (IOException exception)
    {
      throw new KeyManagerException(
          "Unable to write key to keystore : {0}", exception,
          exception.getMessage()
      );
    }

    catch (NoSuchAlgorithmException exception)
    {
      throw new KeyManagerException(
          "Security provider does not support required key store algorithm: {0}", exception,
          exception.getMessage()
      );
    }

    catch (CertificateException exception)
    {
      throw new KeyManagerException(
          "Cannot store certificate: {0}", exception,
          exception.getMessage()
      );
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

        catch (IOException exception)
        {
          securityLog.warn(
              "Failed to close file output stream to keystore : {0}", exception,
              exception.getMessage()
          );
        }
      }
    }
  }


  /**
   * Loads a key store from the given input stream or creates a new instance in case of a
   * null input stream. Configured key storage type and security provider instance are used
   * to load/create the keystore.
   *
   * @param file
   *            file to load the key store from
   *
   * @param password
   *            password to access the key store
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if loading or creating the keystore fails
   */
  private void loadKeyStore(File file, char[] password) throws ConfigurationException,
                                                               KeyManagerException
  {
    // This is basically just a convenience method to actual implementation
    // in loadKeyStore(InputStream, char[])...

    if (file == null)
    {
      throw new KeyManagerException("Implementation Error: null file descriptor.");
    }

    try
    {
      BufferedInputStream in = new BufferedInputStream(new FileInputStream(file));

      loadKeyStore(in, password);
    }

    catch (FileNotFoundException exception)
    {
      throw new KeyManagerException(
          "Keystore file ''{0}'' could not be created or opened : {1}", exception,
          resolveFilePath(file), exception.getMessage()
      );
    }

    catch (SecurityException exception)
    {
      throw new KeyManagerException(
          "Security manager has denied access to keystore file ''{0}'' : {1}", exception,
          resolveFilePath(file), exception.getMessage()
      );
    }
  }


  /**
   * Loads a key store from the given input stream or creates a new instance in case of a
   * null input stream. Configured key storage type and security provider instance are used
   * to load/create the keystore.
   *
   * @param in
   *            input stream to key store file (or null to create a new one)
   *
   * @param password
   *            shared secret (a password) used for protecting access to the key store
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if loading or creating the keystore fails
   */
  private void loadKeyStore(InputStream in, char[] password) throws ConfigurationException,
                                                                    KeyManagerException
  {
    try
    {
      if (provider == null)
      {
        // Use system installed security provider...

        keystore = KeyStore.getInstance(storage.getStorageName());
      }

      else
      {
        keystore = KeyStore.getInstance(storage.getStorageName(), provider);
      }

      keystore.load(in, password);
    }

    catch (KeyStoreException exception)
    {
      // NOTE:  If the algorithm is not recognized by a provider, it is indicated by a nested
      //        NoSuchAlgorithmException. This is the behavior for both SUN default provider
      //        in Java 6 and BouncyCastle.

      if (exception.getCause() != null && exception.getCause() instanceof NoSuchAlgorithmException)
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
            "The security provider(s) '{0}' do not support keystore type '{1}' : {2}", exception,
            usedProviders, storage.name(), exception.getMessage()
        );
      }

      throw new KeyManagerException(
          "Cannot load keystore: {0}", exception,
          exception.getMessage()
      );
    }

    catch (NoSuchAlgorithmException exception)
    {
      // If part of the keystore load() the algorithm to verify the keystore contents cannot
      // be found...

      throw new KeyManagerException(
          "Required keystore verification algorithm not found: {0}", exception,
          exception.getMessage()
      );
    }

    catch (CertificateException exception)
    {
      // Can happen if any of the certificates in the store cannot be loaded...

      throw new KeyManagerException(
          "Can't load keystore: {0}", exception,
          exception.getMessage()
      );
    }

    catch (IOException exception)
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

      // TODO : this error would be improved by reporting file location and keystore type..

      throw new KeyManagerException(
          "I/O Error: Cannot load keystore: {0}", exception,
          exception.getMessage()
      );
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
   * Storage implementations for serializing and persisting private keys, public keys/certificates.
   * <p>
   *
   * Supported storage formats are a selection of formats implemented by Sun's Java Cryptography
   * Extensions (JCE) framework (included as part of Java SDK since version 6) and select
   * keystore storage formats implemented by the BouncyCastle security library, release 1.50
   * or later (unless removed in later versions). <p>
   *
   * More details of Sun/Oracle JCE storage formats can be found in http://bit.ly/1qlv8r4.
   * BouncyCastle (release 1.50) keystore types are defined at
   * http://www.bouncycastle.org/specifications.html
   */
  public enum Storage
  {

    // Sun JCE Provider Storage Formats -----------------------------------------------------------

    /**
     * PKCS #12 format. Used for storing asymmetric key pairs and X.509 public key certificates.
     * Standardized format.
     */
    PKCS12,

    /**
     * A proprietary 'Java Keystore' storage format in Sun Java Cryptography Extension ('SunJCE')
     * implementation. <p>
     *
     * This implementation uses password based encryption with Triple DES. Additional
     * documentation in http://bit.ly/1qybZE9  <p>
     *
     * Can be used for storing symmetric keys, asymmetric key pairs and their associated
     * certificates.
     */
    JCEKS,


    // BouncyCastle Provider Storage Formats ------------------------------------------------------

    /**
     * BouncyCastle keystore format which is roughly equivalent to Sun's 'JKS' keystore format
     * and implementation, and therefore can be used with the standard Java SDK 'keytool'. <p>
     *
     * This format is resistant to tampering but not resistant to inspection, therefore in
     * typical cases the {@link #UBER} storage format is recommended.
     */
    BKS(SecurityProvider.BC),

    /**
     * Recommended BouncyCastle keystore format. Requires password verification and is
     * resistant to inspection and tampering.
     */
    UBER(SecurityProvider.BC);



    // Instance Fields ----------------------------------------------------------------------------

    /**
     * Reference to the security provider with the implementation of the storage. Can be null
     * if no specific provider is used (relying on already installed security providers in the
     * JVM).
     */
    private SecurityProvider provider = null;


    // Constructors -------------------------------------------------------------------------------

    /**
     * Constructs a new storage instance without specific security provider.
     */
    private Storage()
    {
      // no op
    }

    /**
     * Constructs a new storage instance linked to a specific security provider.
     *
     * @param provider
     *            security provider
     */
    private Storage(SecurityProvider provider)
    {
      this.provider = provider;
    }


    // Public Instance Methods --------------------------------------------------------------------


    /**
     * Returns the name of this storage type. <p>
     *
     * For Sun JCE provider implemented storage formats, the standard names are defined in
     * Java security guide: http://bit.ly/1rjfUEI <p>
     *
     * BouncyCastle storage names are defined in BouncyCastle provider documentation.
     *
     * @return  key storage name / format string
     */
    public String getStorageName()
    {
      return name();
    }

    /**
     * Returns the security provider instance associated with this storage implementation. Can
     * return a null if no specific security provider has been associated with the storage
     * instance.
     *
     * @return    security provider instance associated with the storage instance or null if
     *            no specific provider is used
     */
    public Provider getSecurityProvider()
    {
      return (provider == null)
          ? null
          : provider.getProviderInstance();
    }


    // Object Overrides ---------------------------------------------------------------------------

    /**
     * Returns the name of this storage type. <p>
     *
     * For Sun JCE provider implemented storage formats, the standard names are defined in
     * Java security guide: http://bit.ly/1rjfUEI <p>
     *
     * BouncyCastle storage names are defined in BouncyCastle provider documentation.
     *
     * @see #getStorageName
     *
     * @return  key storage name / format string
     */
    @Override public String toString()
    {
      return getStorageName();
    }
  }


  /**
   * Algorithms for generating asymmetric key pairs, as defined in the document:
   * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator <p>
   *
   * Elliptic curve algorithms should be favored for any new implementations that require long
   * term, persistent signature keys. DSA is no longer included as an option and RSA is included
   * to support existing systems, if necessary (see http://bit.ly/1cRMTak for RSA developments). <p>
   *
   * It is worth noting that there currently exists quite a bit of debate around the quality
   * and safety properties of many standard curve specifications typically used with ECC.
   * Much of the discussion can be followed via Safecurves website at
   * http://safecurves.cr.yp.to/index.html.  <p>
   *
   * In particular, the curve specifications originating from NSA / NIST are under criticism
   * for couple of different reasons. One critique is the unexplained seed values that were
   * used to generate the curves, articulated as one of the motivations for creating
   * ECC Brainpool standard curves described here: http://bit.ly/1caBYF4   <p>
   *
   * In addition to the unclear seed value motivation, the NSA / NIST curve properties are
   * criticized for their difficult to implement properties and some safety weaknesses. Some
   * of these arguments are detailed in the presentation here: http://bit.ly/1eG1mYh
   */
  public enum AsymmetricKeyAlgorithm
  {

    /**
     * The default configurations for typical EC providers (i.e. SunEC provider included in Java 7
     * and BouncyCastle provider) often use standard named curves from NSA / NIST / ANSI X9.62 /
     * SECG. This implementation currently defaults to those standard curves but safer curves
     * should be adopted as soon as they're made available as named curves in the security
     * providers. BouncyCastle provider for example may be adding a safer curve 'Curve25519' for
     * example which should be used once available (see discussion here: http://bit.ly/1akHyrX). <p>
     *
     * With the default configuration, the BouncyCastle (release 1.5.0) provider will use the
     * following curves:
     *
     * <ul>
     *  <li>192-bit - NSA / NIST P-192 / ANSI X9.62 (named curve "prime192v1")</li>
     *  <li>224-bit - NSA / NIST P-224 / ANSI X9.62 (named curve "P-224")</li>
     *  <li>239-bit - ANSI X9.62 (named curve "prime239v1")</li>
     *  <li>256-bit - NSA / NIST P-256 / ANSI X9.62 (named curve "prime256v1")</li>
     *  <li>384-bit - NSA / NIST P-384 (named curve "P-384")</li>
     *  <li>521-bit - NSA / NIST P-521 (named curve "P-521")</li>
     * </ul>
     *
     * When no named curve is specified, the 239-bit curve (ANSI X9.62 prime239v1) is used.
     *
     * The SunCE provider (OpenJDK 7) will use following curves:
     *
     * <ul>
     * <li>192-bit - NSA / NIST P-192 (ASN.1 OID 1.2.840.10045.3.1.1)</li>
     * <li>224-bit - NSA / NIST P-224 (ASN.1 OID 1.3.132.0.33)</li>
     * <li>239-bit - ANSI x9.62 prime239v1</li>
     * <li>256-bit - NSA / NIST P-256 (ASN.1 OID 1.2.840.10045.3.1.7)</li>
     * <li>384-bit - NSA / NIST P-384 (ASN.1 OID 1.3.132.0.34)</li>
     * <li>521-bit - NSA / NIST P-521 (ASN.1 OID 1.3.132.0.35)</li>
     * </ul>
     *
     * When no named curve is specified, the 256-bit curve (NSA / NIST P-256) is used. Sun EC provider
     * includes also some shorter bit length curves which should not be used and some other bit
     * lengths above 256 bits not listed here but which are also defined by NSA / NIST.  <p>
     *
     * The 256-bit curve corresponding to 3072-bit asymmetric RSA key strength in combination
     * with 128-bit symmetric AES keys and SHA-2 256-bit message digests are considered adequate
     * for classified information up to secret level (as per NSA Suite B recommendation). Keys
     * with lower strength should not be used.<p>
     *
     * The 384-bit curve corresponds to 7680-bit asymmetric RSA key strength and should be used
     * in combination with 256-bit symmetric AES keys and 384-bit SHA-2 hash. This level of
     * security is currently estimated to be secure beyond year 2030 and can be used for
     * classified information up to top secret level as per NSA suite B recommendation. <p>
     */
    EC(
        new ECGenParameterSpec(ASN_OID_STD_CURVE_NSA_NIST_P521),
        KeySigner.DEFAULT_EC_SIGNATURE_ALGORITHM
    ),

    /**
     * RSA signature/cipher algorithm with key size as specified in
     * {@link PrivateKeyManager#DEFAULT_RSA_KEY_SIZE} and public exponent value as defined in
     * {@link PrivateKeyManager#DEFAULT_RSA_PUBLIC_EXPONENT}.  <p>
     *
     * Note the developments in solving the discrete logarithm problem (see http://bit.ly/1cRMTak)
     * and the increasing RSA key sizes that impact performance. For these reasons, elliptic
     * curves should be preferred.
     */
    RSA(
        new RSAKeyGenParameterSpec(DEFAULT_RSA_KEY_SIZE, DEFAULT_RSA_PUBLIC_EXPONENT),
        KeySigner.DEFAULT_RSA_SIGNATURE_ALGORITHM
    );


    // Instance Fields ----------------------------------------------------------------------------

    /**
     * Key generator algorithm configuration parameters.
     */
    private AlgorithmParameterSpec algorithmSpec;

    /**
     * A default signature algorithm associated with this asymmetric key algorithm.
     */
    private KeySigner.SignatureAlgorithm defaultSignatureAlgorithm;



    // Constructors -------------------------------------------------------------------------------

    /**
     * Constructs a new asymmetric key algorithm enum.
     *
     * @param spec
     *          algorithm parameters
     *
     * @param defaultSignatureAlgorithm
     *          a corresponding default public key signature algorithm to associate with this
     *          asymmetric key algorithm
     */
    private AsymmetricKeyAlgorithm(AlgorithmParameterSpec spec,
                                   KeySigner.SignatureAlgorithm defaultSignatureAlgorithm)
    {
      this.algorithmSpec = spec;
      this.defaultSignatureAlgorithm = defaultSignatureAlgorithm;
    }


    // Instance Methods ---------------------------------------------------------------------------

    /**
     * Returns the algorithm's standard name, see
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @return asymmetric key algorithm standard name
     */
    public String getAlgorithmName()
    {
      return name();
    }


    /**
     * Returns a default public key signature algorithm that should be used with this asymmetric
     * key algorithm.
     *
     * @return  a public key signature algorithm associated with this asymmetric key algorithm
     */
    public KeySigner.SignatureAlgorithm getDefaultSignatureAlgorithm()
    {
      return defaultSignatureAlgorithm;
    }


    // Object Overrides ---------------------------------------------------------------------------

    /**
     * Returns the algorithm's standard name, see
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @see #getAlgorithmName()
     *
     * @return asymmetric key algorithm standard name
     */
    @Override public String toString()
    {
      return getAlgorithmName();
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

