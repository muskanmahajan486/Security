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

import org.openremote.logging.Logger;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

/**
 * Manages the dynamic loading of a security provider implementations.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public enum SecurityProvider
{
  /**
   * BouncyCastle provider.
   */
  BC("org.bouncycastle.jce.provider.BouncyCastleProvider");


  // Class Members --------------------------------------------------------------------------------

  private final static Logger log = Logger.getInstance(SecurityLog.DEFAULT);


  // Instance Fields ------------------------------------------------------------------------------

  private String className;


  // Constructors ---------------------------------------------------------------------------------

  private SecurityProvider(String className)
  {
    this.className = className;
  }

  // Public Instance Methods ----------------------------------------------------------------------

  /**
   * Manages the dynamic loading of a security provider.
   *
   * @return  A provider instance <b>or null</b> if the instance could not be loaded
   */
  public Provider getProviderInstance()
  {
    try
    {
      Class<?> c = Thread.currentThread().getContextClassLoader().loadClass(className);

      Class<? extends Provider> cp = c.asSubclass(Provider.class);

      return cp.newInstance();
    }

    catch (ClassCastException e)
    {
      log.error(
          "The security provider implementation ''{0}'' does not extend Provider class." +
          "Defaulting to system installed security providers: {1}",
          e, className, Arrays.toString(Security.getProviders())
      );

      return null;
    }

    catch (ClassNotFoundException e)
    {
      log.error(
          "The security provider implementation ''{0}'' was not found in classpath. " +
          "Defaulting to system installed security providers: {1}",
          e, className, Arrays.toString(Security.getProviders())
      );

      return null;
    }

    catch (InstantiationException e)
    {
      log.error(
          "The configured security provider ''{0}'' cannot be instantiated: {1}. " +
          "Defaulting to system installed security providers: {2} ",
          e, className, e.getMessage(), Arrays.toString(Security.getProviders())
      );

      return null;
    }

    catch (IllegalAccessException e)
    {
      log.error(
          "The configured security provider ''{0}'' cannot be accessed: {1]." +
          "Defaulting to system installed security providers: {2} ",
          e, className, e.getMessage(), Arrays.toString(Security.getProviders())
      );

      return null;
    }

    catch (ExceptionInInitializerError e)
    {
      log.error(
          "Error initializing security provider class ''{0}'': {1}. " +
          "Defaulting to system installed security providers: {2}",
          e,  className, e.getMessage(), Arrays.toString(Security.getProviders())
      );

      return null;
    }

    catch (SecurityException e)
    {
      log.error(
          "Security manager prevented instantiating security provider class ''{0}'': {1}. " +
          "Defaulting to system installed security providers: {2} " +
          e, className, e.getMessage(), Arrays.toString(Security.getProviders())
      );

      return null;
    }
  }
}

