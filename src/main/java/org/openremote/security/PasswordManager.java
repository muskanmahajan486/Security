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

import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;


/**
 * This is a password storage implementation using Java's keystore mechanism. It can
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

  /**
   * The backing keystore instance.
   *
   * TODO : should push to super class
   */
  private KeyStore keystore = null;


  // Constructors ---------------------------------------------------------------------------------

  /**
   * Constructs an in-memory password manager backed by {@link StorageType#BKS} storage format. <p>
   *
   * Requires BouncyCastle security provider to be available on the classpath and installed
   * as a security provider to the JVM.
   *
   * @see java.security.Security#addProvider(java.security.Provider)
   * @see org.bouncycastle.jce.provider.BouncyCastleProvider
   *
   * @throws ConfigurationException
   *            if the configured security provider(s) do not support {@link StorageType#BKS}
   *            keystore type
   *
   * @throws  KeyManagerException
   *            if creating a new keystore instance fails
   */
  public PasswordManager() throws ConfigurationException, KeyManagerException
  {
    init(StorageType.BKS, SecurityProvider.BC.getProviderInstance());

    this.keystore = createKeyStore();
  }


  /**
   * Constructs a persistent password manager backed by {@link StorageType#BKS} storage format.
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
   *            if the configured security provider(s) do not support {@link StorageType#BKS}
   *            keystore type
   *
   * @throws  KeyManagerException
   *            if loading an existing keystore fails, or creating a new keystore instance
   *            fails
   */
  public PasswordManager(URI keystoreLocation, char[] masterPassword)
      throws ConfigurationException, KeyManagerException
  {
    try
    {
      init(StorageType.BKS, SecurityProvider.BC.getProviderInstance());

      if (keystoreLocation == null)
      {
        throw new KeyManagerException("Implementation error: keystore location URI is null.");
      }

      this.keystoreLocation = keystoreLocation;

      if (exists(keystoreLocation))
      {
        this.keystore = load(keystoreLocation, masterPassword);
      }

      else
      {
        this.keystore = createKeyStore();

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
   * Adds a new password to this password manager.
   *
   * @param alias
   *            A named alias for the password used to look it up.
   *
   * @param password
   *            The password to store. Note that the byte array will be set to zero bytes
   *            when this method completes.
   *
   * @param storeMasterPassword
   *            The master password to access this password storage. Note that the character
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
//    See to-do in add() implementation..
//
//      add(
//          alias,
//          new KeyStore.SecretKeyEntry(new SecretKeySpec(password, "password")),
//          new KeyStore.PasswordProtection(storeMasterPassword)
//      );

      add(alias, password, storeMasterPassword);

      if (keystoreLocation != null)
      {
        save(keystoreLocation, storeMasterPassword);
      }
    }

    finally
    {
      if (password != null)
      {
        // Clear the password from memory...

        for (int i = 0; i < password.length; ++i)
        {
          password[i] = 0;
        }
      }

      if (storeMasterPassword != null)
      {
        // Clear the password from memory...

        for (int i = 0; i < storeMasterPassword.length; ++i)
        {
          storeMasterPassword[i] = 0;
        }
      }
    }
  }

  /**
   * Removes a password from this password storage.
   *
   * @param alias
   *          The password alias (name) to be removed.
   *
   * @param storeMasterPassword
   *          The master password to access this password storage. Note that the character
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

      remove(alias, storeMasterPassword);
    }

    finally
    {
      if (storeMasterPassword != null)
      {
        // Clear the password from memory...

        for (int i = 0; i < storeMasterPassword.length; ++i)
        {
          storeMasterPassword[i] = 0;
        }
      }
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
   * @throws
   */
  public byte[] getPassword(String alias, char[] storeMasterPassword)
      throws PasswordNotFoundException
  {
    try
    {
      if (alias == null || alias.equals(""))
      {
        throw new PasswordNotFoundException(
            "Implementation Error: null or empty password alias."
        );
      }

      if (!keystore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class))
      {
        throw new PasswordNotFoundException(
            "Implementation Error: password alias ''{0}'' does not correspond to secret " +
            "key entry in the keystore.",
            alias
        );
      }

      KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)keystore.getEntry(
          alias, new KeyStore.PasswordProtection(storeMasterPassword)
      );

      return entry.getSecretKey().getEncoded();
    }

    catch (KeyStoreException e)
    {
      throw new PasswordNotFoundException(
          "Implementation Error: password manager has not been loaded."
      );
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new PasswordNotFoundException(e.getMessage(), e);   // TODO
    }

    catch (UnrecoverableKeyException e)
    {
      throw new PasswordNotFoundException(e.getMessage(), e);   // TODO
    }

    catch (UnrecoverableEntryException e)
    {
      throw new PasswordNotFoundException(e.getMessage(), e);   // TODO
    }

    finally
    {
      clearPassword(storeMasterPassword);
    }
  }


  // Private Instance Methods ---------------------------------------------------------------------

  /**
   * Clears the given password character array with zero values.
   *
   * @param password
   *            password character array to erase
   */
  private void clearPassword(char[] password)
  {
    if (password != null)
    {
      for (int i = 0; i < password.length; ++i)
      {
        password[i] = 0;
      }
    }
  }


  private void add(String alias, byte[] password, char[] storeMasterPassword)
      throws KeyManagerException
  {
    // TODO:
    //  This is a bit of a kludge workaround for now until the superclass can be
    //  refactored to manage the underlying keystore instance...

    try
    {
      KeyStore.Entry entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(password, "password"));
      KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(storeMasterPassword);

      add(alias, entry, protection);

      keystore.setEntry(alias, entry, protection);
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException(e.getMessage(), e);
    }

    catch (IllegalArgumentException e)
    {
      throw new KeyManagerException(e.getMessage(), e);
    }
  }

  private void remove(String alias, char[] storeMasterPassword)
      throws KeyManagerException
  {
    // TODO:
    //  This is a bit of a kludge workaround for now until the superclass can be
    //  refactored to manager the underlying keystore instance...

    try
    {
      if (storeMasterPassword == null || storeMasterPassword.length == 0)
      {
        throw new KeyManagerException(
            "Implementation Error: null or empty storage password is not allowed."
        );
      }

      remove(alias);

      keystore.deleteEntry(alias);

      if (keystoreLocation != null)
      {
        keystore.store(
            new BufferedOutputStream(new FileOutputStream(new File(keystoreLocation))),
            storeMasterPassword
        );
      }
    }

    catch (FileNotFoundException e)
    {
      throw new KeyManagerException(
          "Cannot save password manager to ''{0}'': {1}",
          e, keystoreLocation, e.getMessage()
      );
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new KeyManagerException(
          "Keystore algorithm is not supported by installed security providers ({0}): {1}",
          e, Arrays.toString(Security.getProviders()), e.getMessage()
      );
    }

    catch (CertificateException e)
    {
      throw new KeyManagerException("Unable to store certificate: {0}", e, e.getMessage());
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException("Cannot delete password ''{0}'': {1}", e, alias, e.getMessage());
    }

    catch (IOException e)
    {
      throw new KeyManagerException("I/O error while saving password: {0}", e, e.getMessage());
    }

    catch (SecurityException e)
    {
      throw new KeyManagerException(
          "Security manager has prevented saving passwords to ''{0}'' : {1}",
          e, keystoreLocation, e.getMessage()
      );
    }
  }


  // Nested Classes -------------------------------------------------------------------------------

  /**
   * Implementation specific exception type indicating that a requested password was not
   * found in this password manager instance.
   */
  public class PasswordNotFoundException extends OpenRemoteException
  {
    /**
     * Constructs a password not found exception with a given message.
     *
     * @param msg
     *            exception message
     */
    private PasswordNotFoundException(String msg)
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
    private PasswordNotFoundException(String msg, Object... params)
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
    private PasswordNotFoundException(String msg, Throwable cause)
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
    private PasswordNotFoundException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }

}

