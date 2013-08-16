/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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
package wsattacker.plugin.xmlencryptionattack;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.testsuite.RequestResponsePair;

public class XMLEncryptionAttack extends AbstractPlugin {

    private static final String NAME = "XML-Encryption Attack";
    private static final String DESCRIPTION = "Short description of XMl-Encryption attack";
    private static final String AUTHOR = "Dennis Kupser";
    private static final String VERSION = "1.0 / 2013-12-31";
    private static final String[] CATEGORY = new String[] {"Security", "Encryption"};

    @Override
    public void initializePlugin() {
        setName(NAME);
        setDescription(DESCRIPTION);
        setAuthor(AUTHOR);
        setVersion(VERSION);
        setCategory(CATEGORY);
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void clean() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean wasSuccessful() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void attackImplementationHook(RequestResponsePair original) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
