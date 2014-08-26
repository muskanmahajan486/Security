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

import org.openremote.base.exception.OpenRemoteException;

import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.security.KeyStore;


/**
 * This is a password storage implementation using Java's key store mechanism. It can
 * be used in cases where an asymmetric key challenge (normally preferred) based on
 * private key is not an option. <p>
 *
 * Where a password based credentials to access, for example a remote web service is
 * required, this implementation allows storing password credentials in an encrypted
 * format in a keystore implementation. This prevents locating stored passwords via a
 * simple filesystem scan for example. However, it doesn't offer password security
 * beyond hiding the password (obscurity) unless the keystore itself is protected by
 * a master password. For non-interactive applications this creates a chicken-egg
 * problem of storing the master password to access a securely stored passwords unless
 * an external key storage (e.g. smart card, biometric hardware or similar) is present.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class PasswordManager extends KeyManager
{


  // Private Instance Fields ----------------------------------------------------------------------

  /**
   * Location of the keystore, if persisted.
   */
  private URI keystoreLocation = null;


  // Constructors ---------------------------------------------------------------------------------

  /**
   * Constructs an in-memory password manager backed by {@link Storage#UBER} storage format. <p>
   *
   * Requires BouncyCastle security provider to be available on the classpath and installed
   * as a security provider to the JVM.
   *
   * @see java.security.Security#addProvider(java.security.Provider)
   * @see org.bouncycastle.jce.provider.BouncyCastleProvider
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not support {@link Storage#UBER}
   *            keystore type
   *
   * @throws  KeyManagerException
   *            if creating a new keystore instance fails
   */
  public PasswordManager() throws ConfigurationException, KeyManagerException
  {
    super(Storage.UBER, SecurityProvider.BC.getProviderInstance());
  }


  /**
   * Constructs a persistent password manager backed by {@link Storage#UBER} storage format.
   * If no password storage exists at the given URI, a new one will be created. <p>
   *
   * Requires BouncyCastle security provider to be available on the classpath and installed
   * as a security provider to the JVM.
   *
   * @see java.security.Security#addProvider(java.security.Provider)
   * @see org.bouncycastle.jce.provider.BouncyCastleProvider
   *
   * @param keystoreLocation
   *            Location of the persisted password storage.
   *
   * @param masterPassword
   *            The master password to access the password storage. Note that the character
   *            array will be cleared when this constructor completes.
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not support {@link Storage#UBER}
   *            keystore type
   *
   * @throws  KeyManagerException
   *            if loading an existing keystore fails, or creating a new keystore instance
   *            fails
   */
  public PasswordManager(URI keystoreLocation, char[] masterPassword)
      throws ConfigurationException, KeyManagerException
  {
    super(Storage.UBER, SecurityProvider.BC.getProviderInstance());

    try
    {
      if (keystoreLocation == null)
      {
        throw new KeyManagerException("Implementation error: keystore location URI is null.");
      }

      this.keystoreLocation = keystoreLocation;


      if (exists(keystoreLocation))
      {
        load(keystoreLocation, masterPassword);
      }

      else
      {
        save(keystoreLocation, masterPassword);
      }
    }

    finally
    {
      clearPassword(masterPassword);
    }
  }


  // Public Instance Methods ----------------------------------------------------------------------

  /**
   * Adds a new password to this password manager. The password storage is immediately persisted
   * after the add operation using the given master password.
   *
   * @param alias
   *            A named alias of the password for looking it up.
   *
   * @param password
   *            The password to store. Note that the byte array will be set to zero bytes
   *            when this method completes.
   *
   * @param storeMasterPassword
   *            The master password for the password storage. Note that the character
   *            array will be set to zero bytes when this method completes.
   *
   * @throws KeyManagerException
   *            if accessing the password store fails
   */
  public void addPassword(String alias, byte[] password, char[] storeMasterPassword)
      throws KeyManagerException
  {
    try
    {
      KeyStore.Entry entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(password, "password"));
      KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(storeMasterPassword);

      super.add(alias, entry, protection);

      if (keystoreLocation != null)
      {
        save(keystoreLocation, storeMasterPassword);
      }
    }

    catch (IllegalArgumentException exception)
    {
      throw new KeyManagerException(exception.getMessage(), exception);
    }

    finally
    {
      clearPassword(password);
      clearPassword(storeMasterPassword);
    }
  }

  /**
   * Removes a password from this password storage. The password storage is immediately persisted
   * with the given master password as part of this method invocation.
   *
   * @param alias
   *          The password alias (name) to be removed.
   *
   * @param storeMasterPassword
   *          The master password for the password storage. Note that the character
   *          array will be cleared when this method completes.
   *
   * @throws KeyManagerException
   *          if accessing the password store fails
   */
  public void removePassword(String alias, char[] storeMasterPassword) throws KeyManagerException
  {
    try
    {
      if (alias == null)
      {
        return;
      }

      remove(alias);

      if (keystoreLocation != null)
      {
        super.save(keystoreLocation, storeMasterPassword);
      }
    }

    finally
    {
      clearPassword(storeMasterPassword);
    }
  }

  /**
   * Fetches a password from this password storage. The password is returned as a byte array
   * and should be erased immediately after it has been used.
   *
   * @param alias
   *            The password alias used to lookup the required password from the storage.
   *
   * @param storeMasterPassword
   *            The master password to access this password storage. Note that the character
   *            array will be cleared when this method completes.
   *
   * @return    Password in a byte array. This byte array should be erased as soon as the
   *            password has been used.
   *
   * @throws PasswordNotFoundException
   *            if the password could not be retrieved
   */
  public byte[] getPassword(String alias, char[] storeMasterPassword)
      throws PasswordNotFoundException
  {
    try
    {
      if (alias == null || alias.equals(""))
      {
        throw new PasswordNotFoundException("Implementation Error: null or empty password alias.");
      }

      KeyStore.Entry entry = retrieveKey(alias, new KeyStore.PasswordProtection(storeMasterPassword));

      if (!(entry instanceof KeyStore.SecretKeyEntry))
      {
        throw new PasswordNotFoundException(
            "Implementation Error: password alias ''{0}'' does not correspond to secret " +
            "key entry in the keystore.",
            alias
        );
      }

      return ((KeyStore.SecretKeyEntry) entry).getSecretKey().getEncoded();
    }

    catch (KeyManagerException exception)
    {
      throw new PasswordNotFoundException(
          "Password with alias '{0}' could not be retrieved : {1}", exception,
          alias, exception.getMessage()
      );
    }

    finally
    {
      clearPassword(storeMasterPassword);
    }
  }




  // Private Instance Methods ---------------------------------------------------------------------


  // Nested Classes -------------------------------------------------------------------------------

  /**
   * Implementation specific exception type indicating that a requested password was not
   * found in this password manager instance.
   */
  public static class PasswordNotFoundException extends OpenRemoteException
  {
    /**
     * Constructs a password not found exception with a given message.
     *
     * @param msg
     *            exception message
     */
    public PasswordNotFoundException(String msg)
    {
      super(msg);
    }

    /**
     * Constructs a password not found exception with a given parameterized message.
     *
     * @see OpenRemoteException
     *
     * @param msg
     *            exception message
     *
     * @param params
     *            message parameters
     */
    public PasswordNotFoundException(String msg, Object... params)
    {
      super(msg, params);
    }

    /**
     * Constructs a password not found exception with a given message and root cause.
     *
     * @param msg
     *            exception message
     *
     * @param cause
     *            root cause for this exception
     */
    public PasswordNotFoundException(String msg, Throwable cause)
    {
      super(msg, cause);
    }

    /**
     * Constructs a password not found exception with a given parameterized message and root cause.
     *
     * @see OpenRemoteException
     *
     * @param msg
     *            exception message
     *
     * @param cause
     *            root cause for this exception
     *
     * @param params
     *            message parameters
     */
    public PasswordNotFoundException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }

}

