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

import org.openremote.exception.OpenRemoteException;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
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
  private final static SecurityProvider DEFAULT_SECURITY_PROVIDER = SecurityProvider.BC;


  // Enums ----------------------------------------------------------------------------------------

  /**
   * Format for storing, serializing and persisting private and secret key information. Defines
   * the known types as per the document:
   * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#KeyStore <p>
   */
  public enum StorageType
  {
    /**
     * PKCS #12 format
     */
    PKCS12,

    /**
     * Proprietary 'Java Keystore' format (in default 'SUN' provider)
     */
    JKS,

    /**
     * Proprietary 'Java Keystore' format in Java cryptography extension ('SunJCE') provider
     */
    JCEKS,

    /**
     * BouncyCastle keystore format roughly equivalent to Sun JKS implementation.
     */
    BKS;


    // TODO : add the rest of BC keystore options


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
   * Stores key store entries which are used when the contents of this key manager is
   * turned into a keystore implementation (in-memory, file-persisted, or otherwise).
   */
  private Map<String, KeyStoreEntry> keyEntries = new HashMap<String, KeyStoreEntry>();

  /**
   * The storage type used by this instance.
   */
  private StorageType storage = DEFAULT_KEYSTORE_STORAGE_TYPE;

  /**
   * The security provider used by this instance. Note that may contain a null reference in
   * which case implementation should delegate to the the JVM installed security providers
   * in their preferred use order.
   */
  private Provider provider = DEFAULT_SECURITY_PROVIDER.getProviderInstance();


  // Constructors ---------------------------------------------------------------------------------

  /**
   * Empty implementation, no-args constructor limited for subclass use only.
   */
  protected KeyManager()
  {

  }

  /**
   * This constructor allows the subclasses to specify both the storage type and explicit
   * security provider to use with this instance. The storage type and provider will be used
   * instead of the default values. <p>
   *
   * Note that the provider parameter allows a null value. This indicates that the appropriate
   * security provider should be searched from the JVM installed security providers in their
   * preferred order.
   *
   * @param storage
   *            The storage type to use with this instance.
   *
   * @param provider
   *            The explicit security provider to use with the storage of this instance. If a
   *            null value is specified, the implementations should opt to delegate the selection
   *            of a security provider to the JVMs installed security provider implementations.
   */
  protected KeyManager(StorageType storage, Provider provider)
  {
    if (storage == null)
    {
      throw new IllegalArgumentException("Implementation Error: null storage type");
    }

    this.provider = provider;
    this.storage = storage;
  }


  // Protected Instance Methods -------------------------------------------------------------------

  /**
   * Stores the keys in this key manager in a secure keystore format. This implementation generates
   * a file-based, persistent keystore which can be shared with other applications and processes.
   *
   * @param file
   *              the file where the keystore should be saved
   *
   * @param password
   *              A secret password used to access the keystore contents. Note that the character
   *              array will be set to zero values after this method call completes.
   *
   * @return      an in-memory keystore instance
   *
   * @throws ConfigurationException
   *              if the configured security provider(s) do not contain implementation for the
   *              required keystore type
   *
   * @throws KeyManagerException
   *              if loading or creating the keystore fails
   */
  protected KeyStore save(File file, char[] password)
      throws ConfigurationException, KeyManagerException
  {
    if (file == null)
    {
      throw new KeyManagerException("Save failed due to null file descriptor.");
    }

    try
    {
      KeyStore keystore;

      if (exists(file))
      {
        keystore = instantiateKeyStore(file, password);
      }

      else
      {
        keystore = instantiateKeyStore(password);
      }

      BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(file));

      return save(keystore, out, password);
    }

    catch (FileNotFoundException e)
    {
      throw new KeyManagerException(
          "File ''{0}'' cannot be created or opened : {1}", e, resolveFilePath(file), e.getMessage()
      );
    }

    catch (SecurityException e)
    {
      throw new KeyManagerException(
          "Security manager has denied access to file ''{0}'' : {1}",
          e, resolveFilePath(file), e.getMessage()
      );
    }

    finally
    {
      // TODO : push the password clearing responsibility to subclasses...

      if (password != null)
      {
        for (int i = 0; i < password.length; ++i)
        {
          password[i] = 0;
        }
      }
    }
  }


  /**
   * Stores the keys in this key manager in a secure keystore format. This implementation generates
   * an in-memory keystore that is not backed by a persistent storage.
   *
   * @param password
   *            A secret password used to access the keystore contents. Note that the character
   *            array will be set to zero bytes when this method completes.
   *
   * @return    An in-memory keystore instance.
   *
   * @throws ConfigurationException
   *              if the configured security provider(s) do not contain implementation for the
   *              required keystore type
   *
   * @throws KeyManagerException
   *            if the keystore creation fails for any reason
   */
  protected KeyStore save(char[] password) throws ConfigurationException, KeyManagerException
  {
    try
    {
      KeyStore keystore = instantiateKeyStore(password);

      return save(keystore, new ByteArrayOutputStream(), password);
    }

    finally
    {
      // TODO : push the password clearing responsibility to subclasses...

      if (password != null)
      {
        for (int i = 0; i < password.length; ++i)
        {
          password[i] = 0;
        }
      }
    }
  }

  /**
   * Loads an existing keystore from a file.
   *
   * @param file
   *              file descriptor pointing to the keystore
   *
   * @param keystorePassword
   *              The password to access the keystore. Note that the subclasses invoking this
   *              method are responsible for resetting the password character array after use.
   *
   * @return      The loaded keystore instance.
   *
   * @throws ConfigurationException
   *              if the configured security provider(s) do not contain implementation for the
   *              required keystore type
   *
   * @throws KeyManagerException
   *              if loading the keystore fails
   */
  protected KeyStore load(File file, char[] keystorePassword)
      throws ConfigurationException, KeyManagerException
  {
    return instantiateKeyStore(file, keystorePassword);
  }

  /**
   * Instantiate an in-memory, non-persistent keystore.
   *
   * @param password
   *            Password to access the keystore. Note that the subclasses invoking this
   *            method are responsible for resetting the password character array after use.
   *
   * @return    in-memory keystore instance
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if creating the keystore fails
   */
  protected KeyStore instantiateKeyStore(char[] password)
      throws ConfigurationException, KeyManagerException
  {
    return instantiateKeyStore(password, storage);
  }


  /**
   * Adds a key entry to this instance. Use {@link #save(java.io.File, char[])} to persist
   * if desired.
   *
   * @param keyAlias
   *            A lookup name for the keystore entry to be added.
   *
   * @param entry
   *            Keystore entry to be added. Note that accepted entry types depend on the
   *            keystore storage format.
   *
   * @param param
   *            Protection parameters for the keystore entry/alias.
   */
  protected void add(String keyAlias, KeyStore.Entry entry, KeyStore.ProtectionParameter param)
  {
    if (keyAlias == null || keyAlias.equals(""))
    {
      throw new IllegalArgumentException(
          "Implementation Error: null or empty key alias is not allowed."
      );
    }

    if (entry == null)
    {
      throw new IllegalArgumentException(
          "Implementation Error: null keystore entry is not allowed."
      );
    }

    // TODO check if null protection param is ok?

    keyEntries.put(keyAlias, new KeyStoreEntry(entry, param));
  }

  /**
   * TODO
   *
   * @param keyAlias
   *
   * @return
   */
  protected boolean remove(String keyAlias)
  {
    KeyStoreEntry entry = keyEntries.remove(keyAlias);

    return entry != null;
  }

  /**
   * TODO
   *
   * @param keyAlias
   *
   * @param f
   *
   * @param keystorePassword
   *
   * @throws KeyManagerException
   */
  protected void remove(String keyAlias, File f, char[] keystorePassword)
      throws KeyManagerException
  {
    try
    {
      remove(keyAlias);

      KeyStore ks = instantiateKeyStore(f, keystorePassword);

      ks.deleteEntry(keyAlias);

      ks.store(new FileOutputStream(f), keystorePassword);
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new KeyManagerException(
          "Security provider does not support required key store algorithm: {0}",
          e, e.getMessage()
      );
    }

    catch (CertificateException e)
    {
      throw new KeyManagerException("Cannot remove certificate: {0}", e, e.getMessage());
    }

    catch (FileNotFoundException e)
    {
      throw new KeyManagerException(
          "Error in removing key ''{0}'': {1}", e, keyAlias, e.getMessage()
      );
    }

    catch (IOException e)
    {
      throw new KeyManagerException(
          "Unable to remove key ''{0}''. I/O error: {1}",
          e, keyAlias, e.getMessage()
      );
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException(
          "Cannot remove key ''{0}'' from keystore: {1}", e, keyAlias, e.getMessage()
      );
    }

    finally
    {
      if (keystorePassword != null)
      {
        for (int i = 0; i < keystorePassword.length; ++i)
        {
          keystorePassword[i] = 0;
        }
      }
    }
  }


  /**
   * Returns the security provider associated with this key manager. Note that may return a
   * null reference in which case the implementations should delegate the functionality to
   * JVM installed security providers in their preferred use order.
   *
   * @return    security provider instance or <tt>null</tt>
   */
  protected Provider getSecurityProvider()
  {
    return provider;
  }

  /**
   * Checks if keystore exists at given file location.
   *
   * @param file
   *            a keystore file to check
   *
   * @return    true if file exists, false otherwise
   *
   * @throws KeyManagerException
   *            if security manager has denied access to file information
   */
  protected boolean exists(File file) throws KeyManagerException
  {
    // TODO Implementation Note: API should use URIs to avoid file path portability issues
    //
    //File file = new File(uri);

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
   * Instantiate an in-memory, non-persistent keystore with a given algorithm for the storage
   * format.
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
   *            if creating the keystore fails
   */
  private KeyStore instantiateKeyStore(char[] password, StorageType type)
      throws ConfigurationException, KeyManagerException
  {
    return getKeyStore(null, password, type);
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
   * @return    in-memory keystore instance
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not contain implementation for the
   *            required keystore type
   *
   * @throws KeyManagerException
   *            if loading or creating the keystore fails
   */
  private KeyStore instantiateKeyStore(File file, char[] password)
      throws ConfigurationException, KeyManagerException
  {
    return instantiateKeyStore(file, password, storage);
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
    if (password == null || password.length == 0)
    {
      throw new KeyManagerException(
          "Null or empty password. Keystore must be protected with a password."
      );
    }

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

