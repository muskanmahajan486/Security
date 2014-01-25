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
import org.openremote.security.provider.BouncyCastleX509CertificateBuilder;
import org.testng.Assert;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.UUID;

/**
 * Unit tests for {@link org.openremote.security.PasswordManager}
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class PasswordManagerTest
{

  // Test Lifecycle methods -----------------------------------------------------------------------

  @AfterSuite public void clearSecurityProvider()
  {
    Provider p = Security.getProvider("BC");

    if (p != null)
    {
      Assert.fail("Tests did not properly remove BouncyCastle provider.");
    }
  }


  // No-Arg Constructor Tests ---------------------------------------------------------------------

  /**
   * No arg constructor test with basic parameters.
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtor() throws Exception
  {
    char[] pw = new char[] { 'a', '1' };

    PasswordManager mgr = new PasswordManager(pw);

    // check that password was erased....

    for (Character c : pw)
    {
      Assert.assertTrue(c == 0);
    }
  }

  /**
   * No arg constructor test with null password.
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtorNullPassword() throws Exception
  {
    try
    {
      new PasswordManager(null);
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * No arg constructor test with empty password.
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtorEmptyPassword() throws Exception
  {
    try
    {
      new PasswordManager(new char[] {} );
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  // File Constructor Tests -----------------------------------------------------------------------

  /**
   * Test file-persisted password manager with an existing, empty password store.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructor() throws Exception
  {
    // Create an existing, empty keystore...

    TestBKStore store = new TestBKStore();

    File dir = new File(System.getProperty("user.dir"));
    File file = new File(dir, "test.store-" + UUID.randomUUID());
    file.deleteOnExit();

    store.save(file, new char[] { '0' });

    char[] pw = new char[] { '0' };
    PasswordManager mgr = new PasswordManager(file.toURI(), pw);

    // check that password was erased....

    for (Character c : pw)
    {
      Assert.assertTrue(c == 0);
    }
  }

  /**
   * Test file-persisted password manager with an existing password store that contains
   * passwords.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithExistingKeys() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      // Create an existing keystore...

      TestBKStore store = new TestBKStore();

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test.store-" + UUID.randomUUID());
      file.deleteOnExit();

      store.add(
          "foo",
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { '1' }, "test")),
          new KeyStore.PasswordProtection(new char[] { '0' })
      );

      store.save(file, new char[] { '0' });

      char[] pw = new char[] { '0' };
      PasswordManager mgr = new PasswordManager(file.toURI(), pw);

      // check that password was erased....

      for (Character c : pw)
      {
        Assert.assertTrue(c == 0);
      }

      // check that password is found...

      Assert.assertTrue(Arrays.equals(mgr.getPassword("foo", new char[] {'0'}), new byte[] {'1'}));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Test file-persisted password manager constructor loading a keystore that contains
   * non-password entries.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithWrongEntryType() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      // Create an existing keystore...

      AsymmetricKeyManager keys = AsymmetricKeyManager.create();
      Certificate cert = keys.createSelfSignedKey(
          "bar", new char[] {'0'}, new BouncyCastleX509CertificateBuilder(), "test"
      );

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test.store-" + UUID.randomUUID());
      file.deleteOnExit();

      TestBKStore store = new TestBKStore();
      store.add(
          "foo",
          new KeyStore.TrustedCertificateEntry(cert),
          null
      );

      store.save(file, new char[] { '0' });

      PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { '0' });

      try
      {
        mgr.getPassword("bar", new char[] {'0'});

        Assert.fail("should not get here...");
      }

      catch (PasswordManager.PasswordNotFoundException e)
      {
        // expected...
      }
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Test file-persisted password manager constructor against an empty file.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithEmptyFile() throws Exception
  {
    // Create an existing keystore...

    File file = File.createTempFile("openremote", null);

    try
    {
      new PasswordManager(file.toURI(), new char[] { '0' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Test file-persisted password manager constructor against a non-existent file.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithNewFile() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test.store-" + UUID.randomUUID());
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { '0' });

      byte[] password = new byte[] { 'a' };
      char[] masterpassword = new char[] { '0' };

      mgr.addPassword("foo", password, masterpassword);

      // Check that passwords are cleared...
      for (Byte b : password)
      {
        Assert.assertTrue(b == 0);
      }

      for (Character c : masterpassword)
      {
        Assert.assertTrue(c == 0);
      }

      // try to retrieve the password...

      byte[] pw = mgr.getPassword("foo", new char[] { '0' });

      Assert.assertTrue(Arrays.equals(pw, new byte[] { 'a' }));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Test error handling behavior when constructor has a null file descriptor.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithNullURI() throws Exception
  {
    try
    {
      new PasswordManager(null, new char[] { '0' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Test error handling behavior when constructor has a null password.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithNullPassword() throws Exception
  {
    try
    {
      new PasswordManager(File.createTempFile("openremote", null).toURI(), null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Test error handling behavior when constructor has empty password.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructorWithEmptyPassword() throws Exception
  {
    try
    {
      new PasswordManager(File.createTempFile("openremote", null).toURI(), new char[] {});

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  // AddPassword Tests ----------------------------------------------------------------------------

  /**
   * Tests basic password add.
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddPassword() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test-" + UUID.randomUUID());
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { 'b' });

      mgr.addPassword("test", new byte[] { '1' }, new char[] { 'b' });

      byte[] pw = mgr.getPassword("test", new char[] { 'b' });

      Assert.assertTrue(Arrays.equals(pw, new byte[] { '1' }));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Test basic password add without persistence.
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddPasswordInMemory() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager(new char[] { 'b' });

      mgr.addPassword("test", new byte[] { '1' }, new char[] { 'b' });

      byte[] pw = mgr.getPassword("test", new char[] { 'b' });

      Assert.assertTrue(Arrays.equals(pw, new byte[] { '1' }));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Test error handling when adding password with incorrect storage credentials.
   *
   * @throws Exception      if test fails
   */
  @Test public void testAddPasswordWrongPassword() throws Exception
  {
    File dir = new File(System.getProperty("user.dir"));
    File file = new File(dir, "test-" + UUID.randomUUID());
    file.deleteOnExit();

    PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { 'b' });

    try
    {
      mgr.addPassword("test", new byte[] { '1' }, new char[] { 'c' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests error handling when adding password with a null alias.
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddPasswordNullAlias() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test-" + UUID.randomUUID());
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { 'b' });

      mgr.addPassword(null, new byte[] { '1' }, new char[] { 'c' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Tests error handling when adding password with empty alias.
   *
   * @throws Exception      if test fails
   */
  @Test public void testAddPasswordEmptyAlias() throws Exception
  {
    File dir = new File(System.getProperty("user.dir"));
    File file = new File(dir, "test-" + UUID.randomUUID());
    file.deleteOnExit();

    PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { 'b' });

    try
    {
      mgr.addPassword("", new byte[] { '1' }, new char[] { 'c' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests addPassword() error handling when the given password is a null reference.
   *
   * @throws Exception      if test fails
   */
  @Test public void testAddPasswordNullPassword() throws Exception
  {
    File dir = new File(System.getProperty("user.dir"));
    File file = new File(dir, "test-" + UUID.randomUUID());
    file.deleteOnExit();

    PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { 'b' });

    try
    {
      mgr.addPassword("test", null, new char[] { 'c' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests addPassword() error handling when the given password is an empty byte array.
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddPasswordEmptyPassword() throws Exception
  {
    PasswordManager mgr = new PasswordManager(new char[] { 'b' });

    try
    {
      mgr.addPassword("test", new byte[] { }, new char[] { 'c' });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests addPassword() error handling when the store master password is a null.
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddPasswordNullMasterPassword() throws Exception
  {
    File dir = new File(System.getProperty("user.dir"));
    File file = new File(dir, "test-" + UUID.randomUUID());
    file.deleteOnExit();

    PasswordManager mgr = new PasswordManager(file.toURI(), new char[] { 'b' });

    try
    {
      mgr.addPassword("test", new byte[] { '0' }, null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests addPassword() error handling when the store master password is an empty character
   * array.
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddPasswordEmptyMasterPassword() throws Exception
  {
    PasswordManager mgr = new PasswordManager(new char[] { 'b' });

    try
    {
      mgr.addPassword("test", new byte[] { '0' }, new char[] { });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  // Other Tests ----------------------------------------------------------------------------------

  @Test public void testAddAndRemovePassword() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "password-store-" + UUID.randomUUID());
      file.deleteOnExit();
      URI uri = file.toURI();

      char[] masterPassword = new char[] { '1', '2', '3' };

      PasswordManager mgr = new PasswordManager(uri, masterPassword);

      byte[] password = new byte[] { 'a', 'b', 'c', 'd' };
      masterPassword = new char[] { '1', '2', '3' };

      mgr.addPassword("mypassword", password, masterPassword);

      KeyStore ks = KeyStore.getInstance(KeyManager.StorageType.BKS.getStorageTypeName(), new BouncyCastleProvider());

      masterPassword = new char[] { '1', '2', '3' };
      ks.load(new FileInputStream(new File(uri)), masterPassword);

      Assert.assertTrue(ks.containsAlias("mypassword"));
      Assert.assertTrue(ks.size() == 1);

      masterPassword = new char[] { '1', '2', '3' };
      KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(
          "mypassword", new KeyStore.PasswordProtection(masterPassword)
      );

      SecretKey secret = entry.getSecretKey();
      byte[] loadedPassword = secret.getEncoded();
      byte[] originalPassword = new byte[] { 'a', 'b', 'c', 'd' };

      Assert.assertTrue(Arrays.equals(loadedPassword, originalPassword));

      masterPassword = new char[] { '1', '2', '3' };
      mgr.removePassword("mypassword", masterPassword);

      ks = KeyStore.getInstance(KeyManager.StorageType.BKS.getStorageTypeName(), new BouncyCastleProvider());

      masterPassword = new char[] { '1', '2', '3' };
      ks.load(new FileInputStream(new File(uri)), masterPassword);

      Assert.assertTrue(ks.size() == 0);
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  // Nested Classes -------------------------------------------------------------------------------

  private static class TestBKStore extends KeyManager
  {
    private TestBKStore()
    {
      super(StorageType.BKS, new BouncyCastleProvider());
    }
  }
}

