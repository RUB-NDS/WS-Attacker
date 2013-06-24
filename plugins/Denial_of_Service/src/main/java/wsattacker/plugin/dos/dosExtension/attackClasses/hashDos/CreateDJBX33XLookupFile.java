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
package wsattacker.plugin.dos.dosExtension.attackClasses.hashDos;

import java.util.*;

/**
 * Run this file to create a new file with colliding attributenames of DJBX33X
 * Output file with colliding attributenames will be placed in rootfolder of this project
 * WARNING: might run long!
 *
 */
public class CreateDJBX33XLookupFile {

    public static void main(String[] args) {
	
	CollisionDJBX31A collision = new CollisionDJBX31A();
	System.out.println(collision.getHash("tt"));
	System.out.println(collision.getHash("uU"));
	System.out.println(collision.getHash("uUuU"));
	System.out.println(collision.getHash("uUtt"));
	System.out.println(collision.getHash("ttuU"));
	System.out.println(collision.getHash("tttt"));
	
	//CollisionDJBX33X collision = new CollisionDJBX33X();
	//collision.generateCollionsMeetInTheMiddle(1000000);
    }
}