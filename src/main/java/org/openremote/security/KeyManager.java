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

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Abstract superclass with a shared implementation to handle keystore based operations.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public abstract class KeyManager
{

  // Constants ------------------------------------------------------------------------------------

  //
  // TODO : add dynamic classloading so we don't introduce mandatory runtime dependency
  // TODO : let individual subclass instances choose which provider instance to use
  //
  public final static Provider DEFAULT_SECURITY_PROVIDER = new BouncyCastleProvider();


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


  // Private Instance Methods ---------------------------------------------------------------------

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
    if (password == null)
    {
      throw new KeyStoreException("Null password. Keystore must be protected with a password.");
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

}

