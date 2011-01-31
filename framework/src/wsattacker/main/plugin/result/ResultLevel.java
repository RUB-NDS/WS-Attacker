/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.main.plugin.result;

/**
 * Levels for results
 * @author Christian Mainka
 *
 */

/**
 * ResultLevel:
 * Critical: This shall be used as a summary to give a final result, if the attack was successfull
 * Important: This can be used to report important attack steps, e.g. if a part of a plugin was successful
 * Info: Just any information messages
 * Trace: This is for request/response content
 */
public enum ResultLevel {
	Critical, Important, Info, Trace;
}
