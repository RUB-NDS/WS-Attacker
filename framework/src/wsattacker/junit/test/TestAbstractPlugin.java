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

import org.junit.Test;

import wsattacker.junit.util.TestPlugin;
import wsattacker.main.composition.plugin.AbstractPlugin;

import static org.junit.Assert.*;

public class TestAbstractPlugin {
	
	@Test
	public void testEquals() {
		AbstractPlugin a1 = new TestPlugin("a");
		AbstractPlugin a2 = new TestPlugin("a");
		AbstractPlugin b = new TestPlugin("b");
		
		assertTrue(a1.equals(a1));
		assertTrue(a2.equals(a2));
		assertTrue(b.equals(b));
		
		assertFalse(a1 == a2);
		assertTrue(a1.equals(a2));
		
		assertFalse(a1.equals(b));
		assertFalse(a2.equals(b));
	}
}
