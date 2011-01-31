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

package wsattacker.main.plugin;

/**
 * States for a plugin
 * 
 * @author Christian Mainka
 */

/**
 * PluginState:
 * Not_Configured: The plugin needs to be configured (user has to set some options)
 * Ready: The plugin ready for use
 * Aborting: The user has requested to stop the current attack
 * Running: The plugin is just attacking
 * Finished: The plugin is finished
 * Stopped: After the user has requested to abort, the controller will stop the thread if its still alive. The plugin will be set to stopped automatically.
 * Failed: The plugin has any error, e.g. could not start because a file is missing or a port is already in use. 
 */
public enum PluginState {
	Not_Configured, Ready, Aborting, Running, Finished, Stopped, Failed
}
