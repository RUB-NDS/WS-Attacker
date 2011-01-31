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

package wsattacker.util;

import java.lang.reflect.Array;
import java.util.List;


public class Category<Key extends Comparable<Key>, Leaf extends Comparable<Leaf>> implements Comparable<Category<Key, Leaf>> {
	Key name;
	List<Category<Key,Leaf>> subCategorys;
	List<Leaf> leafs;
	
	public Category(Key name) {
		this.name = name;
		this.subCategorys = new SortedUniqueList<Category<Key,Leaf>>();
		this.leafs =  new SortedUniqueList<Leaf>();
	}
	
	public Key getName() {
		return name;
	}
	
	public List<Category<Key,Leaf>> getSubCategorys() {
		return subCategorys;
	}
	
	public Category<Key,Leaf> getSubCategory(Key[] path) {
		Category<Key,Leaf> ret = this;
		for(Key key : path) {
			int index = ret.getSubCategorys().indexOf(new Category<Key, Leaf>(key));
			if(index < 0) {
				ret = null;
				break;
			}
			ret = ret.getSubCategorys().get(index);
		}
		return ret;
	}
	
	public Category<Key,Leaf> getSubCategory(Key key) {
		@SuppressWarnings("unchecked")
		Key[] keys = (Key[]) Array.newInstance(key.getClass(), 1);
		keys[0] = key;
		return getSubCategory(keys);
	}
	
	public Category<Key,Leaf> createPath(Key[] path) {
		Category<Key, Leaf> zwerg = this;
		for(Key key : path) {
			zwerg.createPath(key);
			zwerg = zwerg.getSubCategory(key);
		}
		return zwerg;
	}
	
	public void createPath(Key path) {
		addCategory(new Category<Key, Leaf>(path));
	}
	
	public List<Leaf> getLeafs() {
		return leafs;
	}
	
	public List<Leaf> getLeafsRecursive() {
		List<Leaf> list = new SortedUniqueList<Leaf>();
		list.addAll(getLeafs());
		for(Category<Key,Leaf> sub : subCategorys) {
			list.addAll(sub.getLeafsRecursive());
		}
		return list;
	}
	
	public Object getNode(int index) {
		int subtreeSize = getSubCategorys().size();
		if (index < subtreeSize) {
			return (Object) getSubCategorys().get(index);
		}
		else {
			return (Object) getLeafs().get(index - subtreeSize);
		}
	}
	
	public int getIndexOfNode(Object node) {
		if(getSubCategorys().contains(node)) {
			return getSubCategorys().indexOf(node);
		}
		if(getLeafs().contains(node)) {
			return getSubCategorys().size() + getLeafs().indexOf(node);
		}
		return 0; // should never happen
	}
	
	public int countNodes() {
		return getLeafs().size() + getSubCategorys().size();
	}
	
	public boolean isLeaf(Object node) {
		return getLeafs().contains(node);
	}
	
	public boolean addLeaf(Leaf leaf) {
		return getLeafs().add(leaf);
	}
	
	public boolean removeLeaf(Leaf leaf) {
		return getLeafs().remove(leaf);
	}
	
	public Category<Key, Leaf> addCategory(Category<Key, Leaf> category) {
		Category<Key, Leaf> containedCategory;
		if (getSubCategorys().contains(category)) {
			int containedIndex = getSubCategorys().indexOf(category);
			containedCategory = getSubCategorys().get(containedIndex);
			containedCategory.composeCategory(category);
		} else {
			containedCategory = new Category<Key, Leaf>(category.getName());
			// important: first compose, then add 
			// -> otherwise: c1.addCategory(c1) 
			// would result in infinite recursion
			containedCategory.composeCategory(category);
			getSubCategorys().add(containedCategory);
		}
		return containedCategory;
	}
	
	public Category<Key, Leaf> composeCategory(Category<Key, Leaf> category) {
		getLeafs().addAll(category.getLeafs());
		// we can't use addAll here because we could need composition
		for(Category<Key, Leaf> sub : category.getSubCategorys()) {
			addCategory(sub);
		}
		category.setName(getName());
		category.setSubCategorys(getSubCategorys());
		category.setLeafs(getLeafs());
		return this;
	}
	
	protected void setSubCategorys(List<Category<Key,Leaf>> list) {
		subCategorys = list;
	}
	
	protected void setLeafs(List<Leaf> list) {
		leafs = list;
	}
	
	protected void setName(Key name) {
		this.name = name;
	}
		
	public void removeAllLeafs() {
		getLeafs().clear();
	}
	
	public void removeAllSubCategorys(boolean recursive) {
		if(recursive) {
			for(Category<Key,Leaf> category : getSubCategorys()) {
				category.removeAllLeafs();
				category.removeAllSubCategorys(recursive);
			}
		}
		getSubCategorys().clear();
	}
	
	public void removeAllNodes(boolean recursive) {
		removeAllLeafs();
		removeAllSubCategorys(recursive);
	}

	@Override
	public int compareTo(Category<Key, Leaf> category) {
		return name.compareTo(category.getName());
	}
	
	@SuppressWarnings("unchecked") // this is type save
	@Override
	public boolean equals(Object o) {
		if (o.getClass().isAssignableFrom(getClass()) ) {
			return ((Category<Key, Leaf>)o).getName().equals(this.getName());
		}
		return false;
	}
	
	public void print() {
		print(0);
	}
	
	public void print(int indent) {
		
        // creates a string of 'x' repeating characters
		int count = indent * 4;
        char[] chars = new char[count];
        while (count>0) chars[--count] = ' ';
        String padding = new String(chars);
		
		System.out.format("%s    `-- %s (S:%d|L:%d)\n", padding, getName(), getSubCategorys().size(), getLeafs().size());
		++indent;
		for(Leaf leaf : getLeafs()) {
			System.out.println(padding + "        `-- (+) " + leaf);
		}
		for(Category<Key, Leaf> category : getSubCategorys()) {
			category.print(indent);
		}
	}
	
	@Override
	public String toString() {
		return getName().toString();
	}
}
