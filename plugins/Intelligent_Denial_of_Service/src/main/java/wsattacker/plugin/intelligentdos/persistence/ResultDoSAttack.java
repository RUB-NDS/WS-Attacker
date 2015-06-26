/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos.persistence;

import java.util.List;

import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.dos.DoSAttack;

/**
 * This class is only necessary because we need a concrete DoSAttack to display the infomation on the result page
 * 
 * @author Christian Altmeier
 */
public class ResultDoSAttack
    implements DoSAttack
{

    private String name;

    public List<DoSParam<?>> list;

    public ResultDoSAttack( List<DoSParam<?>> list )
    {
        this.list = list;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getName()
     */
    @Override
    public String getName()
    {
        return name;
    }

    public void setName( String name )
    {
        this.name = name;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getPossiblePossitions()
     */
    @Override
    public PayloadPosition[] getPossiblePossitions()
    {
        return new PayloadPosition[0];
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return false;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#nextParam()
     */
    @Override
    public void nextParam()
    {
        // nothing
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getCurrentParams()
     */
    @Override
    public List<DoSParam<?>> getCurrentParams()
    {
        return list;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getTamperedRequest(java.lang.String,
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public String getTamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        return null;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getUntamperedRequest(java.lang.String,
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public String getUntamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        return null;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#minimal()
     */
    @Override
    public DoSAttack minimal()
    {
        return null;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#middle(wsattacker.library.intelligentdos.dos.DoSAttack)
     */
    @Override
    public DoSAttack middle( DoSAttack doSAttack )
    {
        return null;
    }

    @Override
    public void setUseNamespace( boolean useNamespace )
    {
        // Nothing to do
    }

    @Override
    public void initialize()
    {
        // nothing to do
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#clone()
     */
    @Override
    public ResultDoSAttack clone()
        throws CloneNotSupportedException
    {
        throw new CloneNotSupportedException();
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        return super.hashCode();
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        return super.equals( obj );
    }

    /*
     * 
     */
    @Override
    public int compareTo( DoSAttack o )
    {
        return 0;
    }

}
