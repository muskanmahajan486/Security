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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;

import org.openremote.security.provider.BouncyCastleKeySigner;


/**
 * This is a convenience implementation based on standard Java security architecture and its
 * management of asymmetric key pairs. It provides some helper methods for generating asymmetric
 * key pairs (for example, elliptic curves, RSA) and associated public key X.509 certificates
 * for public key infrastructure. It also provides convenience methods for persistent and
 * in-memory private key stores.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class PrivateKeyManager extends KeyManager
{

  // Constants ------------------------------------------------------------------------------------

  /**
   * The default key algorithm used when generating self-signed key pairs : {@value}
   */
  public static final AsymmetricKeyAlgorithm DEFAULT_SELF_SIGNED_KEY_ALGORITHM =
      AsymmetricKeyAlgorithm.EC;

  public static final String DEFAULT_SELF_SIGNED_KEY_ISSUER = "OpenRemote, Inc.";


  private static final KeySigner keySigner = new BouncyCastleKeySigner();


  // Class Members --------------------------------------------------------------------------------

  /**
   * Creates a new private key manager.
   *
   * @return    key manager instance
   *
   * @throws    ConfigurationException if creating private key manager fails, e.g. the requested
   *            keystore algorithm is not found with the installed security providers.
   */
  public static PrivateKeyManager create() throws ConfigurationException
  {
    return create(DEFAULT_KEYSTORE_STORAGE);
  }

  /**
   * Creates a new private key manager with a given storage format.
   *
   * @param  storage
   *            the desired key storage format
   *
   * @return    key manager instance
   *
   * @throws    ConfigurationException if creating private key manager fails, e.g. the requested
   *            keystore algorithm is not found with the installed security providers.
   */
  public static PrivateKeyManager create(Storage storage) throws ConfigurationException
  {
    try
    {
      return new PrivateKeyManager(storage, storage.getSecurityProvider());
    }

    catch (KeyManagerException exception)
    {
      throw new ConfigurationException(
          "Could not create private key manager : {0}", exception,
          exception.getMessage()
      );
    }
  }

  public static PrivateKeyManager create(Storage storage, SecurityProvider provider)
      throws ConfigurationException
  {
    try
    {
      return new PrivateKeyManager(storage, provider.getProviderInstance());
    }

    catch (KeyManagerException exception)
    {
      throw new ConfigurationException(
          "Could not create private key manager : {0}", exception,
          exception.getMessage()
      );
    }
  }

  public static PrivateKeyManager create(URI keyStoreLocation, char[] masterPassword)
      throws ConfigurationException
  {
    return create(keyStoreLocation, masterPassword, DEFAULT_KEYSTORE_STORAGE);
  }

  public static PrivateKeyManager create(URI keyStoreLocation, char[] masterPassword,
                                         Storage storage) throws ConfigurationException
  {
    try
    {
      return new PrivateKeyManager(keyStoreLocation, masterPassword, storage);
    }

    catch (KeyManagerException exception)
    {
      throw new ConfigurationException(
          "Could not create private key manager : {0}", exception,
          exception.getMessage()
      );
    }
  }



  // Private Instance Fields ----------------------------------------------------------------------

  /**
   * Location of the keystore, if persisted.
   */
  private URI keystoreLocation = null;


  // Constructors ---------------------------------------------------------------------------------

  private PrivateKeyManager(Storage storage, SecurityProvider provider)
      throws KeyManagerException
  {
    this(storage, provider.getProviderInstance());
  }

  /**
   * Internal constructor to be used by the static builder methods.
   */
  private PrivateKeyManager(Storage storage, Provider provider) throws KeyManagerException
  {
    super(storage, provider);
  }

  private PrivateKeyManager(URI keyStoreLocation, char[] masterPassword, Storage storage)
      throws KeyManagerException
  {
    super(keyStoreLocation, masterPassword, storage);

    this.keystoreLocation = keyStoreLocation;
  }

  // Public Instance Methods ----------------------------------------------------------------------


  public Certificate addKey(String keyName, char[] masterPassword) throws KeyManagerException
  {
    return addKey(
        keyName, masterPassword,
        DEFAULT_SELF_SIGNED_KEY_ALGORITHM,
        DEFAULT_SELF_SIGNED_KEY_ISSUER
    );
  }

  public Certificate addKey(String keyName, char[] masterPassword, String issuer)
      throws KeyManagerException
  {
    return addKey(keyName, masterPassword, DEFAULT_SELF_SIGNED_KEY_ALGORITHM, issuer);
  }

  public Certificate addKey(String keyName, char[] masterPassword,
                            AsymmetricKeyAlgorithm keyAlgorithm)
      throws KeyManagerException
  {
    return addKey(keyName, masterPassword, keyAlgorithm, DEFAULT_SELF_SIGNED_KEY_ISSUER);
  }


  public Certificate addKey(String keyName, char[] masterPassword,
                            AsymmetricKeyAlgorithm keyAlgorithm, String issuer)
      throws KeyManagerException
  {
    try
    {
      if (keyName == null || keyName.equals(""))
      {
        throw new KeyManagerException(
            "Implementation error: Null or empty key alias is not allowed."
        );
      }


      // Generate key...

      KeyPair keyPair = generateKey(keyAlgorithm);


      // Sign the public key to create a certificate...

      Certificate certificate = keySigner.signPublicKey(
          KeySigner.Configuration.createDefault(keyPair, issuer)
      );


      // Store the private key and public key + certificate in key store...

      KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
          keyPair.getPrivate(),
          new java.security.cert.Certificate[] { certificate }
      );

      KeyStore.PasswordProtection keyProtection = new KeyStore.PasswordProtection(masterPassword);

      if (masterPassword == null || masterPassword.length == 0)
      {
        keyProtection = null;
      }
    }
  }


  // Private Instance Methods ---------------------------------------------------------------------

  /**
   * Generates a new asymmetric key pair using the given algorithm and algorithm parameters.
   *
   * @param keyAlgo
   *            algorithm for the key generator
   *
   * @return generated key pair
   *
   * @throws KeyGeneratorException
   *            in case any errors in key generation
   */
  private KeyPair generateKey(KeyAlgorithm keyAlgo) throws KeyGeneratorException
  {
    try
    {
      KeyPairGenerator keyGen;

      // TODO :
      //        move keypair generator instance retrieval and KeyAlgorithm enum to
      //        superclass (rename to AsymmetricKeyAlgorithm)

      if (getSecurityProvider() == null)
      {
        keyGen = KeyPairGenerator.getInstance(keyAlgo.getAlgorithmName());
      }

      else
      {
        keyGen = KeyPairGenerator.getInstance(keyAlgo.getAlgorithmName(), getSecurityProvider());
      }

      keyGen.initialize(keyAlgo.spec);

      return keyGen.generateKeyPair();
    }

    catch (InvalidAlgorithmParameterException e)
    {
      throw new KeyGeneratorException(
          "Invalid algorithm parameter in {0} : {1}", e, keyAlgo, e.getMessage()
      );
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new KeyGeneratorException(
          "No security provider found for {0} : {1}", e, keyAlgo, e.getMessage()
      );
    }
  }


  // Nested Classes -------------------------------------------------------------------------------

  /**
   * Specific (internal -- shows up as root cause) exception type for asymmetric
   * key pair generation.
   */
  public static class KeyGeneratorException extends OpenRemoteException
  {
    private KeyGeneratorException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }

}

