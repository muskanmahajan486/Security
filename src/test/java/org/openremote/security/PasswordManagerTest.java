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
import org.openremote.security.provider.BouncyCastleKeySigner;
import org.testng.Assert;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
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
   * No arg constructor test (just code execution completeness)
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtor() throws Exception
  {
    new PasswordManager();
  }


  // File Constructor Tests -----------------------------------------------------------------------

  /**
   * Test file-persisted password manager with an existing, empty password store.
   *
   * @throws Exception    if test fails
   */
  @Test public void testFileConstructor() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());


      // Create an existing, empty keystore...

      TestUBERStore store = new TestUBERStore();

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test.store-" + UUID.randomUUID());
      file.deleteOnExit();

      store.save(file.toURI(), new char[] { '0' });

      char[] pw = new char[] { '0' };
      PasswordManager mgr = new PasswordManager(file.toURI(), pw);

      // check that password was erased....

      for (Character c : pw)
      {
        Assert.assertTrue(c == 0);
      }
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
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

      TestUBERStore store = new TestUBERStore();

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test.store-" + UUID.randomUUID());
      file.deleteOnExit();

      store.add(
          "foo",
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { '1' }, "test")),
          new KeyStore.PasswordProtection(new char[] { '0' })
      );

      store.save(file.toURI(), new char[] { '0' });

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

      PrivateKeyManager keys = PrivateKeyManager.create();
      Certificate cert = keys.addKey("bar", new char[] {'0'}, "test");

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "test.store-" + UUID.randomUUID());
      file.deleteOnExit();

      TestUBERStore store = new TestUBERStore();
      store.add(
          "foo",
          new KeyStore.TrustedCertificateEntry(cert),
          null
      );

      store.save(file.toURI(), new char[] { '0' });

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

      char[] masterPW = new char[] { 'b' };
      PasswordManager mgr = new PasswordManager(file.toURI(), masterPW);

      // Check that the password is cleared...

      for (Character c : masterPW)
      {
        Assert.assertTrue(c == 0);
      }

      masterPW = new char[] { 'b' };
      mgr.addPassword("test", new byte[] { '1' }, masterPW);

      // Check that the password is cleared...

      for (Character c : masterPW)
      {
        Assert.assertTrue(c == 0);
      }

      byte[] pw = mgr.getPassword("test", new char[] { 'b' });

      Assert.assertTrue(Arrays.equals(pw, new byte[] { '1' }));

      TestUBERStore store = new TestUBERStore();
      store.load(file.toURI(), new char[] { 'b' });

      KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)store.retrieveKey(
          "test", new KeyStore.PasswordProtection(new char[] {'b'})
      );

      Assert.assertTrue(Arrays.equals(entry.getSecretKey().getEncoded(), new byte[] { '1' }));

      mgr = new PasswordManager(file.toURI(), new char[] { 'b' });
      pw = mgr.getPassword("test", new char[] { 'b' });

      Assert.assertTrue(Arrays.equals(pw, new byte[] { '1' }));

      mgr.addPassword("tz", new byte[] { 'z' }, new char[] { 'b' });
      mgr.addPassword("tx", new byte[] { 'x' }, new char[] { 'b' });

      ks = store.load(file.toURI(), new char[] { 'b' });

      Assert.assertTrue(ks.containsAlias("tz"));
      Assert.assertTrue(ks.containsAlias("tx"));
      Assert.assertTrue(ks.containsAlias("test"));

      Assert.assertTrue(ks.size() == 3);
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

      PasswordManager mgr = new PasswordManager();

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
    PasswordManager mgr = new PasswordManager();

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
    PasswordManager mgr = new PasswordManager();

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


  // RemovePassword() Tests -----------------------------------------------------------------------

  /**
   * Tests removePassword() with persistence.
   *
   * @throws Exception    if test fails
   */
  @Test public void testRemovePassword() throws Exception
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


      // Remove...

      char[] masterPW = new char[] { 'b' };
      mgr.removePassword("test", masterPW);

      // Check that the password is cleared...

      for (Character c : masterPW)
      {
        Assert.assertTrue(c == 0);
      }

      try
      {
        mgr.getPassword("test", new char[] { 'b' });

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
   * Tests removePassword() consequent calls.
   *
   * @throws Exception    if test fails
   */
  @Test public void testRemovePasswordTwice() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      mgr.addPassword("test", new byte[] { '1' }, new char[] { 'b' });

      byte[] pw = mgr.getPassword("test", new char[] { 'b' });

      Assert.assertTrue(Arrays.equals(pw, new byte[] { '1' }));


      // Remove...

      char[] masterPW = new char[] { 'b' };
      mgr.removePassword("test", masterPW);

      // Check that the password is cleared...

      for (Character c : masterPW)
      {
        Assert.assertTrue(c == 0);
      }

      mgr.removePassword("test", new char[] {'b'});


      try
      {
        mgr.getPassword("test", new char[] {'b'});

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
   * Tests removePassword().
   *
   * @throws Exception    if test fails
   */
  @Test public void testAddAndRemove() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      URI uri = new URI("file", System.getProperty("user.dir") + "/test-" + UUID.randomUUID(), null);
      File file = new File(uri);
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(uri, new char[] { 'b' });

      mgr.addPassword("test1", new byte[] { '1' }, new char[] { 'b' });
      mgr.addPassword("test2", new byte[] { '2' }, new char[] { 'b' });

      TestUBERStore store = new TestUBERStore();
      store.load(uri, new char[] {'b'});

      Assert.assertTrue(ks.size() == 2);
      Assert.assertTrue(ks.containsAlias("test1"));
      Assert.assertTrue(ks.containsAlias("test2"));

      // Remove...

      mgr.removePassword("test1", new char[] { 'b' });

      Assert.assertTrue(Arrays.equals(mgr.getPassword("test2", new char[] { 'b' }), new byte[] { '2' }));

      try
      {
        mgr.getPassword("test1", new char[] {'b'});

        Assert.fail("should not get here...");
      }

      catch (PasswordManager.PasswordNotFoundException e)
      {
        // expected...
      }

      ks = store.load(uri, new char[] { 'b' });

      Assert.assertTrue(ks.size() == 1);
      Assert.assertTrue(ks.containsAlias("test2"));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Tests remove password behavior with a null alias.
   *
   * @throws Exception    if test fails
   */
  @Test public void testRemoveNullAlias() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      // Remove...

      char[] pw = new char[] { 'f', 'o', 'o' };
      mgr.removePassword(null, pw);

      // Check that password is erased...

      for (Character c : pw)
      {
        Assert.assertTrue(c == 0);
      }
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Tests remove password behavior with empty password alias.
   *
   * @throws Exception    if test fails
   */
  @Test public void testRemoveEmptyAlias() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      // Remove...

      char[] pw = new char[] { 'b', '#', 'å' };
      mgr.removePassword("", pw);

      // Check that password is erased...

      for (Character c : pw)
      {
        Assert.assertTrue(c == 0);
      }
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Tests remove password behavior when store password is set to null.
   *
   * @throws Exception    if test fails
   */
  @Test public void testRemoveNullPassword() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      URI uri = new URI("file", System.getProperty("user.dir") + "/test-" + UUID.randomUUID(), null);
      File file = new File(uri);
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(uri, new char[] { 'b' });

      mgr.addPassword("test", new byte[] { '2' }, new char[] { 'b' });

      // Remove...

      try
      {
        mgr.removePassword("test", null);

        Assert.fail("should not get here...");
      }

      catch (KeyManager.KeyManagerException e)
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
   * Tests remove password behavior when the store password is set to empty.
   *
   * @throws Exception    if test fails
   */
  @Test public void testRemoveEmptyPassword() throws Exception
  {
    try
    {
      // BouncyCastle must be installed as a system security provider...

      Security.addProvider(new BouncyCastleProvider());

      URI uri = new URI("file", System.getProperty("user.dir") + "/test-" + UUID.randomUUID(), null);
      File file = new File(uri);
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(uri, new char[] { 'b' });

      mgr.addPassword("test", new byte[] { '2' }, new char[] { 'b' });

      // Remove...

      try
      {
        mgr.removePassword("test", new char[] { });

        Assert.fail("should not get here...");
      }

      catch (KeyManager.KeyManagerException e)
      {
        // expected...
      }
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  // Test GetPassword() --------------------------------------------------------------------------

  /**
   * Basic run through test.
   *
   * @throws Exception    if test fails
   */
  @Test public void testGetPassword() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      mgr.addPassword("testing", new byte[] { 'a', 'b' }, new char[] { '1' });

      byte[] password = mgr.getPassword("testing", new char[] { '1' });

      Assert.assertTrue(Arrays.equals(password, new byte[] { 'a', 'b'}));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Test passwords above the ANSI range.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordSpecialCharacters() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();


      mgr.addPassword("testing1", "ä".getBytes(), new char[] { '1' });

      byte[] password = mgr.getPassword("testing1", new char[] { '1' });

      Assert.assertTrue(Arrays.equals(password, "ä".getBytes()));


      mgr.addPassword("testing2", "∫".getBytes(), new char[] { '1' });

      password = mgr.getPassword("testing2", new char[] { '1' });

      Assert.assertTrue(Arrays.equals(password, "∫".getBytes()));


      mgr.addPassword("testing3", "ç".getBytes(), new char[] { '1' });

      password = mgr.getPassword("testing3", new char[] { '1' });

      Assert.assertTrue(Arrays.equals(password, "ç".getBytes()));


      mgr.addPassword("testing4", "馬".getBytes(), new char[] { '1' });

      password = mgr.getPassword("testing4", new char[] { '1' });

      Assert.assertTrue(Arrays.equals(password, "馬".getBytes()));


      mgr.addPassword("testing5", "ä∫ç馬".getBytes(), new char[] { '1' });

      password = mgr.getPassword("testing5", new char[] { '1' });

      Assert.assertTrue(Arrays.equals(password, "ä∫ç馬".getBytes()));

    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Test getPassword() with null alias.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordNullAlias() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      URI uri = new URI("file", System.getProperty("user.dir") + "/test-" + UUID.randomUUID(), null);
      File file = new File(uri);
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(uri, new char[] { '0' });

      try
      {
        mgr.getPassword(null, new char[] { '1' });

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
   * Test getPassword() with empty alias.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordEmptyAlias() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      URI uri = new URI("file", System.getProperty("user.dir") + "/test-" + UUID.randomUUID(), null);
      File file = new File(uri);
      file.deleteOnExit();

      PasswordManager mgr = new PasswordManager(uri, new char[] { '1' });

      try
      {
        mgr.getPassword("", new char[] { '1' });

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
   * Test getPassword() with empty store master password.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordEmptyMasterPassword() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      try
      {
        mgr.getPassword("foo", new char[] { });

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
   * Test getPassword() with null master password.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordNullMasterPassword() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      try
      {
        mgr.getPassword("foo", null);

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
   * Test error handling behavior when the required keystore algorithm are not present.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordUnrecoverableError() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      PasswordManager mgr = new PasswordManager();

      mgr.addPassword("testing1", new byte[] { 'a' }, new char[] { '1' });

      Security.removeProvider("BC");

      try
      {
        mgr.getPassword("testing1", new char[] {'1'});

        Assert.fail("could not get here...");
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
   * Test error behavior when password manager is used to load a non-secret key keystore entry.
   *
   * @throws Exception if test fails
   */
  @Test public void testGetPasswordNotASecretKey() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      URI uri = new URI("file", System.getProperty("user.dir") + "/test-" + UUID.randomUUID(), null);
      File file = new File(uri);
      file.deleteOnExit();

      PrivateKeyManager mgr = PrivateKeyManager.create();

      mgr.createSelfSignedKey(
          "test", new char[] { 'a' }, new BouncyCastleKeySigner(), "test"
      );

      mgr.save(new char[] { 'a' });

      PasswordManager pwmgr = new PasswordManager(uri, new char[] { 'a' });

      try
      {
        pwmgr.getPassword("test", new char[] { 'a' });

        Assert.fail("could not get here...");
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


  // Test PasswordNotFoundException ---------------------------------------------------------------

  /**
   * Basic run through of the defined exception constructors.
   */
  @Test public void testCtor()
  {
    PasswordManager.PasswordNotFoundException e = new PasswordManager.PasswordNotFoundException("test");

    Assert.assertTrue(e.getMessage().equals("test"));
    Assert.assertTrue(e.getCause() == null);


    e = new PasswordManager.PasswordNotFoundException("test {0}", "test");

    Assert.assertTrue(e.getMessage().equals("test test"));
    Assert.assertTrue(e.getCause() == null);


    e = new PasswordManager.PasswordNotFoundException("test {0}", new Error("foo"));

    Assert.assertTrue(e.getMessage().equals("test {0}"));
    Assert.assertTrue(e.getCause() instanceof Error);
    Assert.assertTrue(e.getCause().getMessage().equals("foo"));


    e = new PasswordManager.PasswordNotFoundException("test {0}", new Error("foo"), "test");

    Assert.assertTrue(e.getMessage().equals("test test"));
    Assert.assertTrue(e.getCause() instanceof Error);
    Assert.assertTrue(e.getCause().getMessage().equals("foo"));
  }


  // Nested Classes -------------------------------------------------------------------------------

  private static class TestUBERStore extends KeyManager
  {
    private TestUBERStore() throws Exception
    {
      super(Storage.UBER, new BouncyCastleProvider());
    }
  }
}

