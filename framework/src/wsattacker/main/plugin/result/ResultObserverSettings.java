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

/**
 * This represents the settings for an result observer
 * It can contain sources and has a level
 * @see ResultLevel
 * @author Christian Mainka
 *
 */
public class ResultObserverSettings {
	ResultLevel level;
	List<String> sources;

	public ResultObserverSettings() {
		this.level = ResultLevel.Important;
		this.sources = new ArrayList<String>();
	}

	public ResultLevel getLevel() {
		return level;
	}

	public void setLevel(ResultLevel level) {
		this.level = level;
	}

	public void addSource(String s) {
		if(!sources.contains(s)) {
			sources.add(s);
		}
	}

	public void removeSource(String s) {
		sources.remove(s);
	}
	
	public List<String> getSources() {
		return sources;
	}
	
	public void setSources(List<String> sources) {
		this.sources = sources;
	}

	/**
	 * Check if log paramter is valid for this settings,
	 * that means:
	 * - log.getSource() is in this.sources
	 * - log.getLevel() >= this.level
	 * 
	 * @param log
	 * @return
	 */
	public boolean check(ResultEntry log) {
		if (this.level.compareTo(log.getLevel()) < 0 )
			return false;
		if (!(this.sources.contains(log.getSource()) || this.sources.isEmpty()))
			return false;
		return true;
	}

}
