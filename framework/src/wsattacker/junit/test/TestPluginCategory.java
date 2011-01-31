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


import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

import wsattacker.gui.util.PluginCategory;
import wsattacker.junit.util.TestPlugin;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.util.Category;

public class TestPluginCategory {
	private static Category<String, AbstractPlugin> root, c1, c2, c3, c4, child, subchild; 

	public void printCategory(Category<String, AbstractPlugin> category, String msg) {
		System.out.println(msg);
		category.print();
		System.out.println("============================================================================");
	}
	
	public void printRoot(String msg) {
		printCategory(root, msg);
	}

	@Before
	public void setUp() throws Exception {
		
		// some references
		child = null;
		subchild = null;
		
		root = new PluginCategory("Root");
		
		c1 = new PluginCategory("A");
		c1.addLeaf(new TestPlugin("c1_1"));
		c1.addLeaf(new TestPlugin("c1_2"));
		
		c2 = new PluginCategory("B");
		c2.addLeaf(new TestPlugin("c2_2"));
		c2.addLeaf(new TestPlugin("c2_1"));
		
		c3 = new PluginCategory("A");
		c3.addLeaf(new TestPlugin("c3_1"));
		
		c4 = new PluginCategory("B");
		c4.addLeaf(new TestPlugin("c4_1"));
		c4.addLeaf(new TestPlugin("c4_2"));
		c4.addCategory(new PluginCategory("S1"));
		c4.addCategory(new PluginCategory("S2"));
	}
	
	private void testOneCategory(Category<String, AbstractPlugin>  category, String expectedName, int expectedSubs, int expectedLeafs) {
		String categoryName = category.getName();
		int categorySubs = category.getSubCategorys().size();
		int categoryLeafs = category.getLeafs().size();
		assertTrue(String.format("Name of '%s' should be %s", categoryName, expectedName), categoryName.equals(expectedName));
		assertTrue(String.format("Category '%s': expected %d sub categorys, but got %d", categoryName, expectedSubs, categorySubs), categorySubs == expectedSubs);
		assertTrue(String.format("Category '%s': expected %d leafs, but got %d", categoryName, expectedLeafs, categoryLeafs), categoryLeafs == expectedLeafs);
		assertTrue(String.format("Category '%s': expected %d sub categorys, but got %d", categoryName, expectedSubs+expectedLeafs, categorySubs+categoryLeafs), (categorySubs+categoryLeafs) == (expectedLeafs+expectedSubs));
	}
	
	private void testAllLeafs(Category<String, AbstractPlugin>  category, String... leaf) {
		int expectedLength = leaf.length;
		int gotLength = category.getLeafs().size();
		assertTrue(String.format("Number of leafs does not match. Expected %d, got %d", expectedLength, gotLength), expectedLength == gotLength);
		for(int i=0; i < gotLength; ++i) {
			String got = category.getLeafs().get(i).getName();
			String expected = leaf[i];
			assertTrue(String.format("Leaf %d does not match, %s != %s", i, got, expected),expected.equals(got));
		}
	}
	
	private void testAllSubs(Category<String, AbstractPlugin>  category, String... sub) {
		int expectedLength = sub.length;
		int gotLength = category.getSubCategorys().size();
		assertTrue(String.format("Number of leafs does not match. Expected %d, got %d", expectedLength, gotLength), expectedLength == gotLength);
		for(int i=0; i < gotLength; ++i) {
			String got = category.getSubCategorys().get(i).getName();
			String expected = sub[i];
			assertTrue(String.format("Sub category %d does not match, %s != %s", i, got, expected),expected.equals(got));
		}
	}
	
	private void testPath(Category<String, AbstractPlugin>  category, String... sub) {
		Category<String, AbstractPlugin> runner, zwerg;
		runner = category;
		for(String key : sub) {
			zwerg = runner.getSubCategory(key);
			assertTrue(String.format("Category %s should have child %s", runner.getName(), key), zwerg != null);
			runner = zwerg;
		}
	}
	
	@Test
	public void testInit() {
		testOneCategory(root, "Root", 0, 0);
	}
	
	@Test
	public void testSimpleComposition() {
		c1.composeCategory(c3);
		testOneCategory(c1, "A", 0, 3);
	}
	
	@Test
	public void testDeepComposition() {
		c1.addCategory(c2);
		c3.addCategory(c4);
		
		c1.composeCategory(c3);
		
//		printCategory(c1, "DeepComposition");
		
		testOneCategory(c1, "A", 1, 3);
		
		child = c1.getSubCategorys().get(0);
		testOneCategory(child, "B", 2, 4);
	}
	
	@Test
	public void testAddCategory() {
		testOneCategory(root, "Root", 0, 0);
				
		// add c1 to root
		root.addCategory(c1);
		printRoot("Root + c1");
		testOneCategory(root, "Root", 1, 0);
		testAllSubs(root, "A");
		
		child = root.getSubCategorys().get(0);
		testOneCategory(child, "A", 0, 2);
		testAllLeafs(child, "c1_1", "c1_2");
		
		// add c2 to root
		root.addCategory(c2);
		printRoot("Root + c1 + c2");
		testOneCategory(root, "Root", 2, 0);
		testAllSubs(root, "A", "B");
		
		// nothing changed for first child
		child = root.getSubCategorys().get(0);
		testOneCategory(child, "A", 0, 2);
		testAllLeafs(child, "c1_1", "c1_2");
		
		// test next child
		child = root.getSubCategorys().get(1);
		testOneCategory(child, "B", 0, 2);
		testAllLeafs(child, "c2_1", "c2_2");
		
		// now composition: "add" c3 to root
		root.addCategory(c3);
		printRoot("Root + c1 + c2 + c3");
		// test root, should not be changed
		testOneCategory(root, "Root", 2, 0);
		testAllSubs(root, "A", "B");
		
		// now leafs
		child = root.getSubCategorys().get(0);
		testOneCategory(child, "A", 0, 3);
		testAllLeafs(child, "c1_1", "c1_2", "c3_1");
		
		// test next child, should not be changed
		child = root.getSubCategorys().get(1);
		testOneCategory(child, "B", 0, 2);
		testAllLeafs(child, "c2_1", "c2_2");
		
		// this should do nothing
		root.composeCategory(root);
		printRoot("Root²");
		testOneCategory(root, "Root", 2, 0);
		testAllSubs(root, "A", "B");
		
		// now leafs
		child = root.getSubCategorys().get(0);
		testOneCategory(child, "A", 0, 3);
		testAllLeafs(child, "c1_1", "c1_2", "c3_1");
		
		// test next child, should not be changed
		child = root.getSubCategorys().get(1);
		testOneCategory(child, "B", 0, 2);
		testAllLeafs(child, "c2_1", "c2_2");
		
		// add categories with sub categories
		root.addCategory(c4);
		printRoot("add categories with sub categories");
		testOneCategory(root, "Root", 2, 0);

		child = root.getSubCategorys().get(0);
		testOneCategory(child, "A", 0, 3);
		
		child = root.getSubCategorys().get(1);
		testOneCategory(child, "B", 2, 4);
		
		subchild = child.getSubCategorys().get(0);
		testOneCategory(subchild, "S1", 0, 0);

		subchild = child.getSubCategorys().get(1);
		testOneCategory(subchild, "S2", 0, 0);
		
	}
	
	@Test
	public void testRecursiveClear() {
		root.addCategory(c1);
		root.addCategory(c2);
		root.addCategory(c3);
		root.addCategory(c4);
		
		c1 = root.getSubCategorys().get(0);
		c2 = root.getSubCategorys().get(1);
		
		root.removeAllNodes(true);
		
		testOneCategory(root, "Root", 0, 0);
		testOneCategory(c1, "A", 0, 0);
		testOneCategory(c2, "B", 0, 0);
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void testGetNode() {
		
		// change root to something that has leafs
		root = c1;
		// add some subcategorys
		root.addCategory(c1);
		root.addCategory(c2);
		
		testOneCategory(root, "A", 2, 2);
		
		child = (Category<String, AbstractPlugin>) root.getNode(0);
		assertTrue(child.getName().equals("A"));
		child = (Category<String, AbstractPlugin>) root.getNode(1);
		assertTrue(child.getName().equals("B"));
		assertTrue(((AbstractPlugin)root.getNode(2)).getName().equals("c1_1"));
		assertTrue(((AbstractPlugin)root.getNode(3)).getName().equals("c1_2"));
		
	}
	
	@Test
	public void testGetRecursiveLeafs() {
		TestPlugin p1,p2,p3,p4,p5,p6;
		PluginCategory category0,category1,category2,category3;
		p1 = new TestPlugin("1");
		p2 = new TestPlugin("2");
		p3 = new TestPlugin("3");
		p4 = new TestPlugin("4");
		p5 = new TestPlugin("5");
		p6 = new TestPlugin("6");
		category0 = new PluginCategory("root");
		category1 = new PluginCategory("A");
		category2 = new PluginCategory("B");
		category3 = new PluginCategory("AA");
		
		category0.addLeaf(p6);
		category1.addLeaf(p5);
		category2.addLeaf(p4);
		category2.addLeaf(p3);
		category3.addLeaf(p2);
		category3.addLeaf(p1);
		
		category2.addCategory(category3);
		category0.addCategory(category1);
		category0.addCategory(category2);
		
		List<AbstractPlugin> expectedLeafs = new ArrayList<AbstractPlugin>();
		expectedLeafs.add(p1);
		expectedLeafs.add(p2);
		expectedLeafs.add(p3);
		expectedLeafs.add(p4);
		expectedLeafs.add(p5);
		expectedLeafs.add(p6);
		
		List<AbstractPlugin> recursiveLeafs = category0.getLeafsRecursive();
		
		assertTrue(expectedLeafs.size() == recursiveLeafs.size());
		expectedLeafs.removeAll(recursiveLeafs);
		assertTrue(expectedLeafs.isEmpty());
		
	}
	
	@Test
	public void testGetSubCategory() {
		c3.addCategory(c4);
		c2.addCategory(c3);
		c1.addCategory(c2);
		root.addCategory(c1);
		
		printRoot("testGetSubCategory()");
		
		child = root.getSubCategory("A");
		assertTrue(child != null);
		testOneCategory(child, "A", 1, 2);
		
		child = root.getSubCategory(new String[] {"A","B","A","B"});
		assertTrue(child != null);
		testOneCategory(child, "B", 2, 2);
	}
	
	@Test
	public void testCreatePath() {
		root = new PluginCategory("root");
		root.createPath(new String[] {"11","22","33","44"});
		printRoot("Path 1");
		testPath(root, "11","22","33","44");
		

		root.createPath(new String[] {"11","22","33","45"});
		printRoot("Path 2");
		testPath(root, "11","22","33","44");
		testPath(root, "11","22","33","45");
		
		root.createPath("12");
		printRoot("Path 3");
		testPath(root, "12");
		testPath(root, "11","22","33","44");
		testPath(root, "11","22","33","45");
		
		root.createPath(new String[] {"11","22","34","45"});
		printRoot("Path 4");
		testPath(root, "11","22","33","44");
		testPath(root, "11","22","33","45");
		testPath(root, "11","22","34","45");
		
	}
}
