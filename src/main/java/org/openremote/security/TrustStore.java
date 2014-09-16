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

import java.net.URI;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;

/**
 * TODO
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class TrustStore extends KeyManager
{


  // Constants ------------------------------------------------------------------------------------

  public static final Storage DEFAULT_TRUST_STORAGE = Storage.BKS;


  // Class Members --------------------------------------------------------------------------------

  public static TrustStore create() throws ConfigurationException
  {
    return create(DEFAULT_TRUST_STORAGE);
  }

  public static TrustStore create(Storage storage) throws ConfigurationException
  {
    try
    {
      return new TrustStore(storage, storage.getSecurityProvider());
    }

    catch (KeyManagerException exception)
    {
      throw new ConfigurationException(
          "Could not create private key manager : {0}", exception,
          exception.getMessage()
      );
    }
  }

  public static TrustStore create(Storage storage, SecurityProvider provider)
      throws ConfigurationException
  {
    try
    {
      return new TrustStore(storage, provider.getProviderInstance());
    }

    catch (KeyManagerException exception)
    {
      throw new ConfigurationException(
          "Could not create certificate trust store : {0}", exception,
          exception.getMessage()
      );
    }
  }

  public static TrustStore create(URI keyStoreLocation) throws ConfigurationException
  {
    return create(keyStoreLocation, DEFAULT_TRUST_STORAGE);
  }

  public static TrustStore create(URI keyStoreLocation, Storage storage)
      throws ConfigurationException
  {
    try
    {
      return new TrustStore(keyStoreLocation, storage);
    }

    catch (KeyManagerException exception)
    {
      throw new ConfigurationException(
          "Could not create certificate trust store : {0}", exception,
          exception.getMessage()
      );
    }
  }


  // Private Instance Fields ----------------------------------------------------------------------

  private URI trustStoreLocation = null;


  // Constructors ---------------------------------------------------------------------------------

  private TrustStore(Storage storage, SecurityProvider provider)
      throws KeyManagerException
  {
    this(storage, provider.getProviderInstance());
  }

  /**
   * Internal constructor to be used by the static builder methods.
   */
  private TrustStore(Storage storage, Provider provider) throws KeyManagerException
  {
    super(storage, provider);
  }

  private TrustStore(URI trustStoreLocation, Storage storage)
      throws KeyManagerException
  {
    super(trustStoreLocation, null, storage);

    this.trustStoreLocation = trustStoreLocation;
  }


  // Public Instance Methods ----------------------------------------------------------------------

  public void addTrustedCertificate(String alias, Certificate cert) throws KeyManagerException
  {
    if (alias == null || alias.equals(""))
    {
      throw new KeyManagerException(
          "Implementation error: Null or empty certificate alias is not allowed."
      );
    }

    // Store the trusted certificate in key store...

    KeyStore.TrustedCertificateEntry certificateEntry = new KeyStore.TrustedCertificateEntry(cert);

    add(alias, certificateEntry, null);

    if (trustStoreLocation != null)
    {
      save(trustStoreLocation, EMPTY_KEY_PASSWORD);
    }
  }

}

