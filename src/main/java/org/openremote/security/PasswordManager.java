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

import org.openremote.security.provider.BouncyCastleX509CertificateBuilder;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.Certificate;

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

  private URI keystoreLocation = null;


  // Constructors ---------------------------------------------------------------------------------

  public PasswordManager()
  {
    super(StorageType.BKS, SecurityProvider.BC.getProviderInstance());
  }


  public PasswordManager(URI keystoreLocation, char[] masterPassword)
  {
    super(StorageType.JCEKS, null);

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

  public void addPassword(String alias, byte[] password, char[] masterPassword)
      throws KeyManagerException
  {
    try
    {
      add(
          alias,
          new KeyStore.SecretKeyEntry(new SecretKeySpec(password, "password")),
          new KeyStore.PasswordProtection(masterPassword)
      );

      if (keystoreLocation != null)
      {
        save(new File(keystoreLocation), masterPassword);
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
    }
  }

  public void removePassword(String alias, char[] masterPassword) throws KeyManagerException
  {
    if (keystoreLocation != null)
    {
      remove(alias, new File(keystoreLocation), masterPassword);
    }

    else
    {
      remove(alias);
    }
  }

}

