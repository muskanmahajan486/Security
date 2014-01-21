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

import org.openremote.logging.LogService;

import java.security.Security;
import java.util.Set;
import java.util.logging.Level;

/**
 * Provides some generic methods to work on JVM installed security providers.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class Providers
{

  /**
   * Main method to print the installed security provider information.
   *
   * @param args    command line args
   */
  public static void main(String... args)
  {
    SecurityConfig sc = new SecurityConfig();
    sc.printProviders();
  }


  // Nested Classes -------------------------------------------------------------------------------

  /**
   * Specific log class to write the provider info to.
   */
  private static class SecurityConfig extends LogService
  {
    /**
     * Always logs to {@link SecurityLog#CONFIGURATION} category.
     */
    private SecurityConfig()
    {
      super(SecurityLog.CONFIGURATION);
    }

    /**
     * Print security provider info to log system console output.
     */
    private void printProviders()
    {
      java.security.Provider[] providers = Security.getProviders();
      StringBuilder builder = new StringBuilder(1024);

      for (java.security.Provider provider : providers)
      {
        builder.append("\nProvider Name: ");
        builder.append(provider.getName());
        builder.append("\n");

        Set<java.security.Provider.Service> services = provider.getServices();

        for (java.security.Provider.Service service : services)
        {
          builder.append("    ");
          builder.append(service.getType());
          builder.append(" : ");
          builder.append(service.getAlgorithm());
          builder.append("\n");
        }
      }

      addConsoleOutput(Level.INFO);
      setLevel(Level.INFO);

      logDelegate.setUseParentHandlers(false);
      logDelegate.log(Level.INFO, builder.toString());
    }
  }
}

