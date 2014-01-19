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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

/**
 * Abstract superclass with a shared implementation to handle keystore based operations.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public abstract class KeyManager
{

  // TODO : add deleteKey


  // Constants ------------------------------------------------------------------------------------

  //
  // TODO : add dynamic classloading so we don't introduce mandatory runtime dependency
  // TODO : let individual subclass instances choose which provider instance to use
  //
  public final static Provider DEFAULT_SECURITY_PROVIDER = new BouncyCastleProvider();


  // Constructors ---------------------------------------------------------------------------------

  /**
   * Empty implementation, no-args constructor limited for subclass use only.
   */
  protected KeyManager()
  {

  }


  // Enums ----------------------------------------------------------------------------------------

  /**
   * Format for storing, serializing and persisting private key information. Defines
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
    JCEKS;


    /**
     * Returns the standard name of this storage type as defined in the keystore standard names
     * Java SE 6 security guide.
     *
     * @return  standard keystore name
     */
    @Override public String toString()
    {
      return name();
    }
  }


  // Class Members --------------------------------------------------------------------------------

  /**
   * Default logger for the security package.
   */
  protected final static Logger securityLog = Logger.getInstance(SecurityLog.DEFAULT);


  // Protected Instance Fields --------------------------------------------------------------------

  /**
   * Stores key store entries which are used when the contents of this key manager is
   * turned into a keystore implementation (in-memory, file-persisted, or otherwise).
   */
  protected Map<String, KeyStoreEntry> keyEntries = new HashMap<String, KeyStoreEntry>();


  // Public Instance Methods ----------------------------------------------------------------------

  /**
   * Stores the keys in this key manager in a secure keystore format. This implementation generates
   * an in-memory keystore that is not backed by a persistent storage. The format used for
   * storing the key entries is PKCS #12.
   *
   * @param password
   *            A secret password used to access the keystore contents. Note that the character
   *            array will be set to zero bytes when this method completes.
   *
   * @return    An in-memory keystore instance.
   *
   * @throws KeyManagerException
   *            if the keystore creation fails for any reason
   */
  public KeyStore save(char[] password) throws KeyManagerException
  {
    try
    {
      KeyStore keystore = instantiateKeyStore(password);

      return save(keystore, new ByteArrayOutputStream(), password);
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException("Keystore could not be created : {0}", e, e.getMessage());
    }

    finally
    {
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
   * a file-based, persistent keystore which can be shared with other applications and processes.
   * The format used for storing the key entries is PKCS #12.
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
   * @throws KeyManagerException
   *              if the keystore creation fails for any reason
   */
  public KeyStore save(File file, char[] password) throws KeyManagerException
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

    catch (KeyStoreException e)
    {
      throw new KeyManagerException(
          "Cannot create the key store implementation : {0}", e, e.getMessage()
      );
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
      if (password != null)
      {
        for (int i = 0; i < password.length; ++i)
        {
          password[i] = 0;
        }
      }
    }
  }


  // Protected Instance Methods -------------------------------------------------------------------

  protected void add(String keyAlias, KeyStore.Entry entry, KeyStore.ProtectionParameter param)
  {
    keyEntries.put(keyAlias, new KeyStoreEntry(entry, param));
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
          "Unable to write key to keystore : {1}", e, e.getMessage()
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
   * Instantiante an in-memory, non-persistent PKCS #12 keystore.
   *
   * @param password
   *            password to access the keystore
   *
   * @return    in-memory keystore instance
   *
   * @throws KeyStoreException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(char[] password) throws KeyStoreException
  {
    return instantiateKeyStore(password, StorageType.PKCS12);   // TODO : define default store type
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
   * @throws KeyStoreException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(char[] password, StorageType type) throws KeyStoreException
  {
    return getKeyStore(null, password, type);
  }

  /**
   * Loads a PKCS #12 keystore instance from an existing file.
   *
   * @param file
   *            file to load the keystore from
   *
   * @param password
   *            password to access the keystore
   *
   * @return    in-memory keystore instance
   *
   * @throws KeyManagerException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(File file, char[] password) throws KeyManagerException
  {
    return instantiateKeyStore(file, password, StorageType.PKCS12);
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
   * @throws KeyManagerException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(File file, char[] password, StorageType type)
      throws KeyManagerException
  {
    try
    {
      BufferedInputStream in = new BufferedInputStream(new FileInputStream(file));

      return getKeyStore(in, password, type);
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException(
          "Keystore could not be created : {0}", e, e.getMessage()
      );
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
   * @throws java.security.KeyStoreException
   *            if the provided security provider does not contain implementation for the
   *            required keystore type, or loading the keystore fails for any other reason
   */
  private KeyStore getKeyStore(InputStream in, char[] password, StorageType type)
      throws KeyStoreException
  {
    if (password == null || password.length == 0)
    {
      throw new KeyStoreException(
          "Null or empty password. Keystore must be protected with a password."
      );
    }

    try
    {
      KeyStore keystore = KeyStore.getInstance(type.name(), DEFAULT_SECURITY_PROVIDER);
      keystore.load(in, password);

      return keystore;
    }
    catch (NoSuchAlgorithmException e)
    {
      // If the configured provider(s) do not recognize the keystore format...

      throw new KeyStoreException(
          "Required keystore algorithm '" + type.toString() + "' not found: " +
          e.getMessage(), e
      );
    }
    catch (CertificateException e)
    {
      // Can happen if any of the certificates in the store cannot be loaded...

      throw new KeyStoreException("Can't load keystore: " + e.getMessage(), e);
    }
    catch (IOException e)
    {
      // If there's an I/O problem, or if keystore has been corrupted, or if password is missing

      if (e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException)
      {
        throw new KeyStoreException(
            "Cannot recover keys from keystore (was the provided password correct?) : " +
            e.getMessage(), e
        );
      }

      throw new KeyStoreException("Can't load keystore: " + e.getMessage(), e);
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

  /**
   * Checks if given file exists.
   *
   * @param file
   *            file to check
   *
   * @return    true if file exists, false otherwise
   *
   * @throws KeyManagerException
   *            if security manager has denied access to file information
   */
  private boolean exists(final File file) throws KeyManagerException
  {
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

}

