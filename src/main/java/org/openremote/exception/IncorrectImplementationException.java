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
package org.openremote.exception;

/**
 * A runtime (unchecked) exception type to indicate implementation errors (code paths that
 * should not be reached under normal conditions). Differentiating the exception type to make
 * it easier to distinguish from other predefined exception types that may originate for example
 * from third party libraries. This allows clear distinction between OpenRemote error conditions
 * and other errors that may be handled separately.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class IncorrectImplementationException extends OpenRemoteRuntimeException
{


  // TODO : Should be moved to a base package once one is created   [JPL]

  /**
   * Constructs a new implementation exception with a given message.
   *
   * @param msg
   *          human-readable error message
   */
  public IncorrectImplementationException(String msg)
  {
    super(msg);
  }

  /**
   * Constructs a new implementation exception with a parameterized message.
   *
   * @param msg
   *          human-readable error message
   *
   * @param params
   *          exception message parameters -- message parameterization must be
   *          compatible with {@link java.text.MessageFormat} API
   *
   * @see java.text.MessageFormat
   */
  public IncorrectImplementationException(String msg, Object... params)
  {
    super(msg, params);
  }

  /**
   * Constructs a new implementation exception with a given message and root cause.
   *
   * @param msg
   *          human-readable error message
   *
   * @param cause
   *          root exception cause
   */
  public IncorrectImplementationException(String msg, Throwable cause)
  {
    super(msg, cause);
  }

  /**
   * Constructs a new implementation exception with a parameterized message and root cause.
   *
   * @param msg
   *          human-readable error message
   *
   * @param cause
   *          root exception cause
   *
   * @param params
   *          exception message parameters -- message parameterization must be
   *          compatible with {@link java.text.MessageFormat} API
   *
   * @see java.text.MessageFormat
   */
  public IncorrectImplementationException(String msg, Throwable cause, Object... params)
  {
    super(format(msg, params), cause);
  }

}

