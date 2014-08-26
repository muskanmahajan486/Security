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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

import org.openremote.security.provider.BouncyCastleKeySigner;

import org.testng.Assert;
import org.testng.annotations.Test;


/**
 * Unit tests for {@link PrivateKeyManager} class.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class PrivateKeyManagerTest
{

  // CreateSelfSignedKey Tests --------------------------------------------------------------------

  /**
   * Basic test to demonstrate the creation of a certificate.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedKey() throws Exception
  {
    char[] keypassword = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
    String alias = "mykey";

    PrivateKeyManager keyManager = PrivateKeyManager.create();

    Certificate cert1 = keyManager.createSelfSignedKey(
        alias, keypassword, new BouncyCastleKeySigner(), "testIssuer"
    );

    Assert.assertTrue(cert1 instanceof X509Certificate);

    // Make sure password is erased in memory...

    for (char c : keypassword)
    {
      Assert.assertTrue(c == 0);
    }
  }


  /**
   * Adds multiple new keys into the keystore manager.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testMultipleSelfSignedKeys() throws Exception
  {
    char[] keypassword2 = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '2' };
    String alias2 = "mykey2";

    PrivateKeyManager keystore = PrivateKeyManager.create();

    Certificate cert2 = keystore.createSelfSignedKey(
        alias2, keypassword2, new BouncyCastleKeySigner(), "testIssuer"
    );

    // Make sure password is erased in memory...

    for (char c : keypassword2)
    {
      Assert.assertTrue(c == 0);
    }

    char[] keypassword3 = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '3' };
    String alias3 = "mykey3";

    Certificate cert3 = keystore.createSelfSignedKey(
        alias3, keypassword3, new BouncyCastleKeySigner(), "testIssuer"
    );

    // Make sure password is erased in memory...

    for (char c : keypassword2)
    {
      Assert.assertTrue(c == 0);
    }

    Assert.assertNotNull(cert2);
    Assert.assertNotNull(cert3);

    Assert.assertTrue(cert2 instanceof X509Certificate);
    Assert.assertTrue(cert3 instanceof X509Certificate);

    Assert.assertTrue(!cert2.equals(cert3));
  }

  /**
   * Test a key alias null password which is allowed.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testNullPassword() throws Exception
  {
    String alias2 = "mykey2";

    PrivateKeyManager keystore = PrivateKeyManager.create();

    Certificate cert = keystore.createSelfSignedKey(
        alias2, null, new BouncyCastleKeySigner(), "testInMemoryKeyStore"
    );

    Assert.assertNotNull(cert);
    Assert.assertTrue(cert instanceof X509Certificate);
  }

  /**
   * Test a keystore null key alias which should *not* be allowed.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testNullKey() throws Exception
  {
    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.createSelfSignedKey(
          null, null, new BouncyCastleKeySigner(), "testInMemoryKeyStore"
      );

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....
    }
  }

  /**
   * Test a keystore empty string key alias which should *not* be allowed.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testEmptyKey() throws Exception
  {
    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.createSelfSignedKey(
          "", null, new BouncyCastleKeySigner(), "testInMemoryKeyStore"
      );

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....
    }
  }

  /**
   * Test a certificate builder null reference.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testNullCertBuilder() throws Exception
  {
    char[] keypassword = new char[] { 'a', 'b', 'c' };
    String alias2 = "mykey2243";

    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.createSelfSignedKey(
          alias2, keypassword, null, "testInMemoryKeyStore-2243"
      );

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....

      for (char c : keypassword)
      {
        Assert.assertTrue(c == 0);
      }
    }
  }


  /**
   * Test a null issuer name.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testNullIssuerName() throws Exception
  {
    char[] keypassword = new char[] { 'f', 'd', 's', '5', '_', '1' };
    String alias2 = "mykey5221";

    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.createSelfSignedKey(
          alias2, keypassword, new BouncyCastleKeySigner(), null
      );

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....

      for (char c : keypassword)
      {
        Assert.assertTrue(c == 0);
      }
    }
  }

  /**
   * Test a empty string issuer name.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testEmptyIssuerName() throws Exception
  {
    char[] keypassword = new char[] { 'f', 'd', 's', '5', '_', '1' };
    String alias2 = "mykey5221";

    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.createSelfSignedKey(
          alias2, keypassword, new BouncyCastleKeySigner(), ""
      );

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....

      for (char c : keypassword)
      {
        Assert.assertTrue(c == 0);
      }
    }
  }
  

   // TODO : test certificate contents

  /**
   * Tests storing of keys into an in-memory keystore format.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testInMemoryKeystore() throws Exception
  {
    char[] keypassword1 = new char[] { 'F', 'o', 'o', 'B', 'a', 'r' };
    String alias1 = "key1";

    PrivateKeyManager keyMgr = PrivateKeyManager.create();

    Certificate cert1 = keyMgr.createSelfSignedKey(
        alias1, keypassword1, new BouncyCastleKeySigner(), "testIssuer"
    );


    char[] keypassword2 = new char[] { 'F', 'o', 'o', 'b', 'a', 'r' };
    String alias2 = "key2";

    Certificate cert2 = keyMgr.createSelfSignedKey(
        alias2, keypassword2, new BouncyCastleKeySigner(), "testIssuer2"
    );

    char[] storePW = new char[] { 'f', 'o', 'o', 'b', 'a', 'r' };
    KeyStore keystore = keyMgr.save(storePW);


    // Make sure the password is erased from memory...

    for (char c : storePW)
    {
      Assert.assertTrue(c == 0);
    }

    Assert.assertTrue(keystore.size() == 2);

    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));

    // check the public key certificates...

    Certificate cert = keystore.getCertificate("key1");

    Assert.assertTrue(cert.equals(cert1));
    Assert.assertTrue(cert.getPublicKey().equals(cert1.getPublicKey()));


    cert = keystore.getCertificate("key2");

    Assert.assertTrue(cert.equals(cert2));
    Assert.assertTrue(cert.getPublicKey().equals(cert2.getPublicKey()));
    Assert.assertTrue(cert.getPublicKey() instanceof ECPublicKey);
    Assert.assertTrue(cert.getPublicKey().getAlgorithm().equals(PrivateKeyManager.KeyAlgorithm.EC.name()));

    String alias = keystore.getCertificateAlias(cert1);

    Assert.assertTrue(alias.equals("key1"));

    alias = keystore.getCertificateAlias(cert2);

    Assert.assertTrue(alias.equals("key2"));


    Certificate[] chain = keystore.getCertificateChain("key1");

    Assert.assertTrue(chain.length == 1);

    Assert.assertTrue(keystore.isKeyEntry("key1"));
    Assert.assertTrue(keystore.isKeyEntry("key2"));


    // convert in-memory keystore to file-based...

    File f = File.createTempFile("openremote", null);
    FileOutputStream fout = new FileOutputStream(f);
    BufferedOutputStream bout = new BufferedOutputStream(fout);

    storePW = new char[] { 'f', 'o', 'o', '_', 'b', 'a', 'r' };
    keystore.store(bout, storePW);

    Assert.assertTrue(f.exists());


    // Retrieve password protected private keys...

    keypassword1 = new char[] { 'F', 'o', 'o', 'B', 'a', 'r' };

    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key1",
        new KeyStore.PasswordProtection(keypassword1)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);
    Assert.assertTrue(entry.getPrivateKey() instanceof ECPrivateKey);
    Assert.assertTrue(entry.getPrivateKey().getAlgorithm().equals(PrivateKeyManager.KeyAlgorithm.EC.name()));

    keypassword2 = new char[] { 'F', 'o', 'o', 'b', 'a', 'r' };

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key2",
        new KeyStore.PasswordProtection(keypassword2)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);
    Assert.assertTrue(entry.getPrivateKey() instanceof ECPrivateKey);
    Assert.assertTrue(entry.getPrivateKey().getAlgorithm().equals(PrivateKeyManager.KeyAlgorithm.EC.name()));
  }


  /**
   * Tests key manipulation operations.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testInMemoryKeystoreOperations() throws Exception
  {

    PrivateKeyManager keyMgr = PrivateKeyManager.create();

    // Add two keys...

    char[] keypassword = new char[] { 'a', 'C', 'm', '3'};
    String alias1 = "key1";

    keyMgr.createSelfSignedKey(
        alias1, keypassword, new BouncyCastleKeySigner(), "testIssuer"
    );

    String alias2 = "key2";

    keyMgr.createSelfSignedKey(
        alias2, new char[] {}, new BouncyCastleKeySigner(), "testIssuer2"
    );


    // Convert to keystore...

    char[] storePW = new char[] { 'f', 'o', 'o'};
    KeyStore keystore = keyMgr.save(storePW);

    Assert.assertTrue(keystore.size() == 2);
    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));


    // Add two additional keys...

    String alias3 = "key3";

    keyMgr.createSelfSignedKey(
        alias3, new char[] {}, new BouncyCastleKeySigner(), "testIssuer3"
    );

    String alias4 = "key4";

    keyMgr.createSelfSignedKey(
        alias4, new char[] {}, new BouncyCastleKeySigner(), "testIssuer4"
    );

    // Convert to keystore...

    storePW = new char[] { 'f', 'o', 'o'};
    keystore = keyMgr.save(storePW);

    Assert.assertTrue(keystore.size() == 4);

    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));
    Assert.assertTrue(keystore.containsAlias("key3"));
    Assert.assertTrue(keystore.containsAlias("key4"));



    // Add a key with existing alias... (should override)

    String alias5 = "key2";

    keyMgr.createSelfSignedKey(
        alias5, new char[] {}, new BouncyCastleKeySigner(), "testIssuer3"
    );

    String alias6 = "key6";

    keyMgr.createSelfSignedKey(
        alias6, new char[] {}, new BouncyCastleKeySigner(), "testIssuer4"
    );


    // Convert to keystore instance....

    keystore = keyMgr.save(new char[] { 0 });

    Assert.assertTrue(keystore.size() == 5, "expected 5 keys, found " + keystore.size());

    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));
    Assert.assertTrue(keystore.containsAlias("key3"));
    Assert.assertTrue(keystore.containsAlias("key4"));
    Assert.assertTrue(keystore.containsAlias("key6"));


    // retrieve password protected private key entry...

    keypassword = new char[] { 'a', 'C', 'm', '3' };

    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key1",
        new KeyStore.PasswordProtection(keypassword)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key2",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key3",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key4",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key6",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);
  }


  /**
   * Tests storing and loading a keystore from a file-system.
   *
   * @throws Exception  if test fails
   */
  @Test public void testFileKeyStore() throws Exception
  {
    PrivateKeyManager keyMgr = PrivateKeyManager.create();

    char[] keypassword = new char[] { 'a', 'C', 'm', '3'};
    String alias1 = "key1";

    keyMgr.createSelfSignedKey(
        alias1, keypassword, new BouncyCastleKeySigner(), "testIssuer"
    );

    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    char[] storePW = new char[] { 'f', 'o', 'o'};

    keyMgr.save(f.toURI(), storePW);

    // Make sure the password is erased from memory after the API call...

    for (char c : storePW)
    {
      Assert.assertTrue(c == 0);
    }

    KeyStore loadStore = KeyStore.getInstance(PrivateKeyManager.StorageType.PKCS12.name());

    storePW = new char[] { 'f', 'o', 'o'};
    loadStore.load(new BufferedInputStream(new FileInputStream(f)), storePW);

    Assert.assertTrue(loadStore.size() == 1);
    Assert.assertTrue(loadStore.containsAlias("key1"));
  }


  /**
   * Runs basic test to ensure the key algorithm names are consistent across
   * name(), toString() and getAlgorithmName()
   */
  @Test public void testKeyAlgorithmNames()
  {
    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.EC.name().equals(PrivateKeyManager.KeyAlgorithm.EC.toString())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.EC.toString().equals(PrivateKeyManager.KeyAlgorithm.EC.getAlgorithmName())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.EC.getAlgorithmName().equals(PrivateKeyManager.KeyAlgorithm.EC.name())
    );


    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.RSA.name().equals(PrivateKeyManager.KeyAlgorithm.RSA.toString())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.RSA.toString().equals(PrivateKeyManager.KeyAlgorithm.RSA.getAlgorithmName())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.RSA.getAlgorithmName().equals(PrivateKeyManager.KeyAlgorithm.RSA.name())
    );

  }
}

