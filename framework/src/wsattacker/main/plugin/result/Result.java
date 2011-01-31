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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Collection;
import java.util.Iterator;

import wsattacker.main.composition.ResultObserver;

/**
 * The Result class is a container for ResultEntries
 * @see ResultEntry
 * @author Christian Mainka
 *
 */
public class Result implements Collection<ResultEntry> {

	private static Result globalLog = new Result();
	
	List<ResultEntry> log;
	Map<ResultObserver, ResultObserverSettings> observers;
	
	/**
	 * It is possible to generate a new result container
	 */
	public Result() {
		log = new ArrayList<ResultEntry>();
		observers = new HashMap<ResultObserver, ResultObserverSettings>();
	};
	
	/**
	 * The global result is a singleton
	 * It will be used for all generated results
	 * @return
	 */
	public static Result getGlobalResult() {
		return globalLog;
	}
	
	/**
	 * Get by index
	 * @param index
	 * @return ResultEntry
	 */
	public ResultEntry get(int index) {
		return log.get(index);
	}
	
	/**
	 * Return e new Result() which contains the same results but 
	 * without those matching the parameter sources
	 * @param sources
	 * @return
	 */
	public Result filterOut(List<String> sources) {
		Result ret = new Result();
		for (ResultEntry l : this.log) {
			if ( ! sources.contains(l.getSource()) )
				ret.add(l);
		}
		return ret;
	}
	
	public Result filterOut(String source) {
		Result ret = new Result();
		for (ResultEntry l : this.log) {
			if ( ! l.getSource().equals(source) )
				ret.add(l);
		}
		return ret;
	}
	
	/**
	 * Returns a new Result() which contains the same results but 
	 * without those having a lower level than the parameter
	 * @param level
	 * @return
	 */
	public Result filterOut(ResultLevel level) {
		Result ret = new Result();
		for (ResultEntry l : this.log) {
			if ( l.getLevel().compareTo(level) > 0)
				ret.add(l);
		}
		return ret;
	}
	
	/**
	 * Complementary operation to filterOnly
	 * @param source
	 * @return
	 */
	public Result filterOnly(String source) {
		Result ret = new Result();
		for (ResultEntry l : this.log) {
			if ( l.getSource().equals(source) )
				ret.add(l);
		}
		return ret;
	}

	/**
	 * Complementary operation to filterOnly
	 * @param sources
	 * @return
	 */
	public Result filterOnly(List<String> sources) {
		Result ret = new Result();
		for (ResultEntry l : this.log) {
			if ( sources.contains(l.getSource()) )
				ret.add(l);
		}
		return ret;
	}

	/**
	 * Complementary operation to filterOnly
	 * @param sources
	 * @return
	 */
	public Result filterOnly(ResultLevel level) {
		Result ret = new Result();
		for (ResultEntry l : this.log) {
			if ( l.getLevel().compareTo(level) <= 0 )
				ret.add(l);
		}
		return ret;
	}
	
	// Observer Stuff
	
	public boolean registerObserver(ResultObserver o) {
		if ( ! this.observers.containsKey(o) )
		{
			this.observers.put(o, new ResultObserverSettings());
			return true;
		}
		return false;
	}
	
	public boolean removeObserver(ResultObserver o) {
		if ( this.observers.containsKey(o) )
		{
			this.observers.remove(o);
			return true;
		}
		return false;
	}
	
	public void setObserverLevel(ResultObserver o, ResultLevel level) {
		this.observers.get(o).setLevel(level);
	}
	
	public void addObserverLogSource(ResultObserver o, String source) {
		this.observers.get(o).addSource(source);
	}
	
	public void removeObserverLogSource(ResultObserver o, String source) {
		this.observers.get(o).removeSource(source);
	}
	
	public List<String> getSoures(ResultObserver o) {
		return this.observers.get(o).getSources();
	}
	
	public void setSources(ResultObserver o ,List<String> sources) {
		this.observers.get(o).setSources(sources);
	}
	
	private void notifyObserversAdd(ResultEntry newResult) {
		for ( Map.Entry<ResultObserver, ResultObserverSettings> entry : this.observers.entrySet() ) {
			ResultObserver o = entry.getKey();
			ResultObserverSettings s = entry.getValue();
			if ( s.check(newResult) )
				o.logUpdate(newResult);
		}
	}
	
	private void notifyObserversClear() {
		for ( Map.Entry<ResultObserver, ResultObserverSettings> entry : this.observers.entrySet() ) {
			entry.getKey().logClear();
		}
	}
	
	// Collection Interface

	@Override
	public Iterator<ResultEntry> iterator() {
		return this.log.iterator();
	}

	@Override
	public boolean add(ResultEntry arg0) {
//		Logger.getLogger(Result.class).log(arg0.getLevel(), String.format("{%s} %s", arg0.getSource(), arg0.getContent()));
		boolean ret = this.log.add(arg0);
		notifyObserversAdd(arg0);
		return ret;
	}

	@Override
	public boolean addAll(Collection<? extends ResultEntry> arg0) {
		boolean ret = true;
		for(ResultEntry l : arg0) {
			ret &= add(l);
		}
		return ret;
	}

	@Override
	public void clear() {
		this.log.clear();
		notifyObserversClear();
		
	}

	@Override
	public boolean contains(Object arg0) {
		return this.log.contains(arg0);
	}

	@Override
	public boolean containsAll(Collection<?> arg0) {
		return this.log.containsAll(arg0);
	}

	@Override
	public boolean isEmpty() {
		return this.log.isEmpty();
	}

	@Override
	public boolean remove(Object arg0) {
//		return this.log.remove(arg0);
		return false;
	}

	@Override
	public boolean removeAll(Collection<?> arg0) {
//		return this.log.removeAll(arg0);
		return false;
	}

	@Override
	public boolean retainAll(Collection<?> arg0) {
		return this.log.retainAll(arg0);
	}

	@Override
	public int size() {
		return this.log.size();
	}

	@Override
	public Object[] toArray() {
		return this.log.toArray();
	}

	@Override
	public <T> T[] toArray(T[] arg0) {
		return this.log.toArray(arg0);
	}
	
	@Override
	public String toString() {
		StringBuffer b = new StringBuffer();
		for (ResultEntry l : this.log)
			b.append(l.toString()).append("\n");
		return new String(b);
	}
}
