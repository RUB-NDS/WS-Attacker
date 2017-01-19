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
package wsattacker.plugin.dos.dosExtension.mvc.controller;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import wsattacker.plugin.dos.dosExtension.result.ResultGenerator;

/**
 * open Helpmenu in Browser
 * 
 * @author af
 */
public class HelpController
    implements ActionListener
{
    private ResultGenerator resultGenerator;

    public HelpController( ResultGenerator resultGenerator )
    {
        this.resultGenerator = resultGenerator;
    }

    @Override
    public void actionPerformed( ActionEvent e )
    {
        resultGenerator.openHelpmenu();
    }
}
