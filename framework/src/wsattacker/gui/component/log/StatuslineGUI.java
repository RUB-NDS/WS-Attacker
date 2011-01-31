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

import java.awt.Color;

import javax.swing.BorderFactory;
import javax.swing.JLabel;

import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.spi.LoggingEvent;

import wsattacker.gui.util.Colors;

public class StatuslineGUI extends JLabel {
	private static final long serialVersionUID = 1L;
	Layout layout;
	
	public StatuslineGUI() {
		super();
		this.layout = new PatternLayout("[%p] %m%n");
		this.setBackground(Colors.INVALID);
		this.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY), BorderFactory.createEmptyBorder(2,10,2,10)));
	}
	
	public void setLog(LoggingEvent loggingEvent) {
		this.setText(layout.format(loggingEvent));
		if(loggingEvent.getLevel().isGreaterOrEqual(Level.WARN)) {
			this.setOpaque(true);
		}
		else {
			this.setOpaque(false);
		}
	}
}
