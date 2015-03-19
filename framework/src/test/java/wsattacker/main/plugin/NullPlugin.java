/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main.plugin;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.testsuite.RequestResponsePair;

public class NullPlugin
    extends AbstractPlugin
{

    private static final long serialVersionUID = 1L;

    private String name, description;

    private int maxPoints;

    public NullPlugin( String name )
    {
        this( name, "", 0 );
    }

    public NullPlugin( String name, String description, int maxPoints )
    {
        this.name = name;
        this.description = description;
        this.maxPoints = maxPoints;
    }

    @Override
    public void initializePlugin()
    {
        // TODO Auto-generated method stub
    }

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public String getDescription()
    {
        return description;
    }

    @Override
    public int getMaxPoints()
    {
        return maxPoints;
    }

    @Override
    protected void attackImplementationHook( RequestResponsePair request )
    {
        // TODO Auto-generated method stub
    }

    @Override
    public void clean()
    {
        // TODO Auto-generated method stub
    }

    @Override
    public boolean wasSuccessful()
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getAuthor()
    {
        return "Test";
    }

    @Override
    public String getVersion()
    {
        return "1";
    }

    @Override
    public String[] getCategory()
    {
        return new String[] { "Test" };
    }
    // @Override
    // public String toString() {
    // return String.format("%5s / %2d / %s", getName(), getMaxPoints(),
    // getDescription());
    // }
}
