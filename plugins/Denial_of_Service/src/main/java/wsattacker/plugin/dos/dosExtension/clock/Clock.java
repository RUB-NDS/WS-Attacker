/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.plugin.dos.dosExtension.clock;


/**
 * Cheap Clock
 * calculates based on "startTime" elapsed time, once reset is called...
 * via update() new time is returned via String!
 * 
 * WARNING: Requires clock Object to be persistent during runtime!
 * 			Kein Problem, wird bei StartAttack erzeugt wird Ticker übergeben, und dort auch referenziert!
 *
 */
public class Clock
{
    private long startTime;

    public Clock()
    {
        reset();
    }

    public String update()
    {
        long elapsedTime = System.currentTimeMillis() - startTime;
        long seconds = elapsedTime / 1000;
        long milliSecs = elapsedTime % 1000; // 1000
        String prefix;
        if(milliSecs < 10)
        {
            prefix = "00";
        }
        else if(milliSecs < 100)
        {
            prefix = "0";
        }
        else
        {
            prefix = "";
        }
        return seconds+""; //+ ":" + prefix + milliSecs;
    }

    public void reset()
    {
        startTime = System.currentTimeMillis();
        update();
    }
}
