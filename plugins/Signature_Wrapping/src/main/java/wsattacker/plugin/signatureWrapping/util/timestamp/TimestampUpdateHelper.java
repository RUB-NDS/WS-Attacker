/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.plugin.signatureWrapping.util.timestamp;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import org.apache.ws.security.util.XmlSchemaDateFormat;

/**
 *
 * @author christian
 */
public class TimestampUpdateHelper {
	private String start, end;

	public TimestampUpdateHelper(String originalStart, String originalEnd) throws ParseException {
      // 1) Detect if Timestamp uses milliseconds
      // /////////////////////////////////////////
      // milliseconds format contains a dot followed by the ms
      boolean inMilliseconds = originalStart.indexOf('.') > 0;
      // 2) Create a Date formater
      // //////////////////////////
	  DateFormat zulu;
      if (inMilliseconds)
      {
        zulu = new XmlSchemaDateFormat();
      }
      else
      {
        zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
      }
      // 3) Parse the dates
      // ///////////////////
      Calendar created = Calendar.getInstance();
      Calendar expires = Calendar.getInstance();

      created.setTime(zulu.parse(originalStart));
      expires.setTime(zulu.parse(originalEnd));

      // 4) Compute Difference = TTL
      // ////////////////////////////
      int diff = (int) ((expires.getTimeInMillis() - created.getTimeInMillis()) / 1000);

      // 5) Update Created/Expires according to detected format and TTL
      // ///////////////////////////////////////////////////////////////
      created = Calendar.getInstance();
      expires = Calendar.getInstance();
      expires.add(Calendar.SECOND, diff);
      // 6) Saves values in Elements
      // ////////////////////////////
      start = zulu.format(created.getTime());
      end   = zulu.format(expires.getTime());
	}

	/**
	 * @return the start
	 */
	public String getStart() {
		return start;
	}

	/**
	 * @return the end
	 */
	public String getEnd() {
		return end;
	}
}
