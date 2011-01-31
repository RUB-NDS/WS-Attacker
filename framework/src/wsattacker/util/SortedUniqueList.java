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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class SortedUniqueList<T extends Comparable<T>> extends ArrayList<T>  {
	private static final long serialVersionUID = 1L;
	
	/***
	 * Creates a new Sorted Unique List.
	 * Comparator will be used to for sorting and detecting duplicates
	 * @param comparator
	 */
	public SortedUniqueList() {
		super();
	}
	
	/***
	 * Does nothing.
	 * Inserting at specific positions is not allowed in sorted lists 
	 */
	@Override
	public void add(int index, T element) {
		return;
	}
	@Override
	public boolean addAll(int index, Collection<? extends T> c) {
		return false;
	}
	
	@Override
	public boolean add(T element) {
		if(contains(element))
			return false;
		boolean tf = super.add(element); // should be always true
		Collections.sort(this);
		return tf;
	}
	
	@Override
	public boolean addAll(Collection<? extends T> c) {
		boolean ret = false;
		for(T element : c) {
			ret |= add(element);
		}
		return ret;
	}
}
