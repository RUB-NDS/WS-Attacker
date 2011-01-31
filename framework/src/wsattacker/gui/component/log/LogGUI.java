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

package wsattacker.gui.component.log;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.apache.log4j.Layout;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.spi.LoggingEvent;

public class LogGUI extends JScrollPane {
	
	private static final long serialVersionUID = 1L;
	JTextArea content;
	Layout layout;
	
	public LogGUI() {
		super();
		setName("Log");
		this.content = new JTextArea();
		this.content.setEditable(false);
		setViewportView(content);
		this.layout = new PatternLayout("%d{ABSOLUTE} %-5p [%c{1}] %m%n");
	}
	public void appendLog(LoggingEvent loggingEvent) {
		content.append(layout.format(loggingEvent));
	}
}
