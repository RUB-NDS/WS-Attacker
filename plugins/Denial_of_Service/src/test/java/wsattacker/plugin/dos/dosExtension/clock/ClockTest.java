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

import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;


/**
 *
 * @author Andreas Falkenberg
 */
public class ClockTest {
    
    Clock instance;
    
    public ClockTest() {
	instance = new Clock();
    }
    

    /**
     * tests if update of clock works
     * update clock after 1 sec and check if incremented by 1
     */
    @Test
    public void testUpdate() {
	System.out.println("update");
	String str1 = instance.update();
	try {
	    Thread.sleep(1000);
	} catch (InterruptedException ex) {
	    Logger.getLogger(ClockTest.class.getName()).log(Level.SEVERE, null, ex);
	}
	String str2 = instance.update();
	
	
	if(str1.equals("0") && !str2.equals("0")) {
	    assertTrue(true);
	} else {
	    assertTrue(false);
	}
    }

    /**
     * Test if clock resets to 0 after several updates!
     */
    @Test
    public void testReset() {
	System.out.println("reset");
	
	try {
	    instance.update();
	    Thread.sleep(1000);
	    instance.update();
	} catch (InterruptedException ex) {
	    Logger.getLogger(ClockTest.class.getName()).log(Level.SEVERE, null, ex);
	}

	String preResult = instance.update();
	instance.reset();
	String result = instance.update();
	
	if(result.equals("0") && !preResult.equals("0")) {
	    assertTrue(true);
	} else {
	    assertTrue(false);
	}	
    }
}
