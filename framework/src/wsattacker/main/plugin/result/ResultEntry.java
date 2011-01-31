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

import java.util.Date;

import wsattacker.util.DateFormater;

/**
 * A Result is a kind of a log entry,
 * @author Christian Mainka
 *
 */
public class ResultEntry implements Comparable<ResultEntry> {
	Date date;
	ResultLevel level;
	String content;
	String source;
	
	public ResultEntry(ResultLevel level, String source, String content) {
		this.level = level;
		this.source = source;
		this.content = content;
		this.date = new Date();
	}


	/**
	 * Each result has a level to describe its verbosity
	 * @return
	 */
	public ResultLevel getLevel() {
		return this.level;
	}

	public Date getDate() {
		return this.date;
	}

	/**
	 * Get the source where this result comes from
	 * Source is only a representative string (no object reference)
	 * @return
	 */
	public String getSource() {
		return this.source;
	}
	
	public String getContent() {
		return this.content;
	}

	@Override
	/**
	 * comparing logs means comparing their dates
	 */
	public int compareTo(ResultEntry o) {
		return this.date.compareTo(o.getDate());
	}
	
	@Override
	public String toString() {
		return String.format("%5s | %s | {%s} %s", this.level, DateFormater.timeonly(this.date), this.source, this.content); // this.level + ")" + "\t# " + this.date + " // " + this.source + " : " + this.content; 
	}
	
}
