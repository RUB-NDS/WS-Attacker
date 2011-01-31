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

import org.apache.log4j.WriterAppender;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Simple example of creating a Log4j appender that will write to a JTextArea.
 */
public class GuiAppender extends WriterAppender {

	private static StatuslineGUI statusbar = new StatuslineGUI();
	private static LogGUI log = new LogGUI();
	
	public GuiAppender() {
	}

	public static StatuslineGUI getStatusbar() {
		return statusbar;
	}

	public static LogGUI getLog() {
		return log;
	}

	@Override
	/**
	 * Format and then append the loggingEvent to the stored
	 * JTextArea.
	 */
	public void append(LoggingEvent loggingEvent) {
		statusbar.setLog(loggingEvent);
		log.appendLog(loggingEvent);
	}
}