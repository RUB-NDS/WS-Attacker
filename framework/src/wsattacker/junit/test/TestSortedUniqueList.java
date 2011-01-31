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

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import wsattacker.junit.util.TestPlugin;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.util.SortedUniqueList;

public class TestSortedUniqueList {

	private static SortedUniqueList<AbstractPlugin> list;
	private static TestPlugin p1,p2,p3,p4;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		list = new SortedUniqueList<AbstractPlugin>();
		p1 = new TestPlugin("Eins", "Erstes eingefügtes Plugin", 1);
		p2 = new TestPlugin("Zwei", "Zweites eingefügtes Plugin", 1);
		p3 = new TestPlugin("Drei", "Drittes eingefügtes Plugin", 1);
		p4 = new TestPlugin("Eins", "Dublikat vom ersten Plugin", 1);
	}

	@Before
	public void setUp() throws Exception {
		list.clear();
	}
	
	@Test
	public void clear() {
		assertTrue("List should be empty", list.size() == 0);
	}
	
	@Test
	public void add() {
		list.add(p1);
		assertTrue("List should contain 1 Element", list.size() == 1);
		list.add(p2);
		assertTrue("List should contain 2 Elements", list.size() == 2);
		list.add(p3);
		assertTrue("List should contain 3 Elements", list.size() == 3);
	}
	
	@Test
	public void unique() {
		list.add(p1);
		assertTrue("List should contain 1 Element", list.size() == 1);
		list.add(p3);
		assertTrue("List should contain 2 Elements", list.size() == 2);
		list.add(p4);
		assertTrue("List not should contain double Elements", list.size() == 2);
	}
	
	@Test
	public void addAll() {
		list.add(p1);
		list.add(p2);
		list.add(p3);
		list.addAll(list);
		assertTrue("List not should contain double Elements" + list, list.size() == 3);
	}
	
	@Test
	public void sorted() {
		list.add(p1);
		list.add(p2);
		list.add(p3);
		
		for(int i=0; i < (list.size()-1); ++i) {
			assertTrue("Elements should be sorted", list.get(i).getName().compareTo(list.get(i+1).getName()) < 0);
		}
	}

}
