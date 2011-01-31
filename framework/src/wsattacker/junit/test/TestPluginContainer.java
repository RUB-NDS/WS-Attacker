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

package wsattacker.junit.test;


import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import wsattacker.junit.util.TestPlugin;
import wsattacker.main.plugin.PluginContainer;
import static org.junit.Assert.*;

public class TestPluginContainer {

	private static PluginContainer plugins;
	private static TestPlugin p1,p2;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		plugins = new PluginContainer();
		p1 = new TestPlugin("Eins", "Erstes eingefügtes Plugin", 1);
		p2 = new TestPlugin("Zwei", "Zweites eingefügtes Plugin", 1);
	}
	
	@Before
	public void setUp() throws Exception {
		plugins.clear();
		plugins.add(p1);
		plugins.add(p2);
	}
	
	@Test
	public void getByName() {
		assertTrue(plugins.getByName("Zwei") == p2);
		assertTrue(plugins.getByName("Vier") == null);
	}
	
	@Test
	public void contains() {
		assertTrue(plugins.contains(p1));
		assertTrue(plugins.contains(p2));
	}

}
