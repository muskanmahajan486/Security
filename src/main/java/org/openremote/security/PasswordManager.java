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

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.net.URI;
import java.security.KeyStore;


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


  // Constructors ---------------------------------------------------------------------------------

  /**
   * Constructs an in-memory password manager backed by {@link StorageType#BKS} storage format.
   * Requires BouncyCastle security provider to be available on the classpath and installed
   * as a security provider to the JVM.
   *
   * @see java.security.Security#addProvider(java.security.Provider)
   * @see org.bouncycastle.jce.provider.BouncyCastleProvider
   */
  public PasswordManager()
  {
    super(StorageType.BKS, SecurityProvider.BC.getProviderInstance());
  }

  /**
   * Constructs a persistent password manager back by {@link StorageType#BKS} storage format.
   * Requires BouncyCastle security provider to be available on the classpath and installed
   * as a security provider to the JVM.
   *
   * @see java.security.Security#addProvider(java.security.Provider)
   * @see org.bouncycastle.jce.provider.BouncyCastleProvider
   *
   * @param keystoreLocation
   *          location of the persisted password storage
   *
   * @param masterPassword
   *          the password to access the password storage
   */
  public PasswordManager(URI keystoreLocation, char[] masterPassword)
  {
    this();

    try
    {
      if (masterPassword == null || masterPassword.length == 0)
      {
        throw new IllegalArgumentException(
            "Implementation error: keystore master password is null or empty."
        );
      }

      if (keystoreLocation == null)
      {
        throw new IllegalArgumentException("Implementation error: keystore location URI is null.");
      }

      this.keystoreLocation = keystoreLocation;

    }

    finally
    {
      if (masterPassword != null)
      {
        // Clear the password from memory...

        for (int i = 0; i < masterPassword.length; ++i)
        {
          masterPassword[i] = 0;
        }
      }
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
      add(
          alias,
          new KeyStore.SecretKeyEntry(new SecretKeySpec(password, "password")),
          new KeyStore.PasswordProtection(storeMasterPassword)
      );

      if (keystoreLocation != null)
      {
        save(new File(keystoreLocation), storeMasterPassword);
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
   *          The master password to access this password storage.
   *
   * @throws KeyManagerException
   *          if accessing the password store fails
   */
  public void removePassword(String alias, char[] storeMasterPassword) throws KeyManagerException
  {
    try
    {
      if (keystoreLocation != null)
      {
        remove(alias, new File(keystoreLocation), storeMasterPassword);
      }

      else
      {
        removePassword(alias);
      }
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


  public void removePassword(String alias)
  {
    remove(alias);
  }

}

